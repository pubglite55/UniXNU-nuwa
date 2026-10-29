#!/usr/bin/env python3
"""Qualify Turnip cache import without executing a shader or contacting hardware.

Requires the built host Turnip and the software peer from check-turnip-darwin-host.py.
Each cache case is a fresh process with Mesa's disk shader cache disabled. The
consumer must succeed under FAIL_ON_PIPELINE_COMPILE_REQUIRED and report an
application cache hit. This does not qualify cross-build cache portability.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'build/turnip-darwin-host'
LIBRARY = ROOT / 'build/mesa-tu/src/freedreno/vulkan/libvulkan_freedreno.dylib'
IOS = ROOT / 'build/mesa-tu-ios/src/freedreno/vulkan/libvulkan_freedreno.dylib'
SHIM = OUT / 'libhostiokit.dylib'
SHADERS = ROOT / 'build/turnip-smoke/NativeTurnipShaders.h'
for required in [LIBRARY, SHIM, SHADERS]:
    if not required.is_file():
        raise SystemExit('Build the host Turnip/peer/own shader fixtures first: ' + str(required))


def binary_identity(path):
    data = path.read_bytes()
    if struct.unpack_from('<I', data)[0] != 0xfeedfacf:
        raise SystemExit('Expected a thin little-endian Mach-O64: ' + str(path))
    count, size = struct.unpack_from('<II', data, 16)
    offset, end = 32, 32 + size
    if end > len(data):
        raise SystemExit('Truncated Mach-O load commands')
    cpu, subtype = struct.unpack_from('<II', data, 4)
    if cpu != 0x100000c or subtype != 0:
        raise SystemExit('Expected ordinary ARM64 subtype 0: ' + str(path))
    result = dict(sha256=hashlib.sha256(data).hexdigest(), cpu_type=cpu, cpu_subtype=subtype)
    for _ in range(count):
        command, length = struct.unpack_from('<II', data, offset)
        if length < 8 or offset + length > end:
            raise SystemExit('Invalid Mach-O load command')
        if command == 0x1b and length == 24:  # LC_UUID
            result['macho_uuid'] = data[offset + 8:offset + 24].hex()
        if command == 0x32 and length >= 24:  # LC_BUILD_VERSION
            result['platform'] = struct.unpack_from('<I', data, offset + 8)[0]
        offset += length
    if offset != end or 'macho_uuid' not in result:
        raise SystemExit('Missing/invalid Mach-O UUID')
    return result


executable = OUT / 'pipeline_cache'
subprocess.run(['xcrun', 'clang++', '-std=c++23', '-O1', '-Wall', '-Wextra', '-Werror',
                '-Wno-unused-parameter', '-Wno-unused-const-variable', '-I', '/opt/homebrew/include',
                '-I', SHADERS.parent, ROOT / 'drivers/Adreno740/tests/hostsim/pipeline_cache.cpp',
                '-o', executable], check=True)
env = {k: v for k, v in os.environ.items() if not k.startswith(('IR3_', 'FD_MESA_', 'NIR_', 'TU_', 'HOSTSIM_', 'MESA_'))}
env.update(DYLD_INSERT_LIBRARIES=str(SHIM), MESA_SHADER_CACHE_DISABLE='true', MESA_LOG='')
report = dict(evidence='host Turnip compilation/cache import over software kernel transport; no shader execution',
              host=binary_identity(LIBRARY),
              own_shader_header_sha256=hashlib.sha256(SHADERS.read_bytes()).hexdigest(),
              cross_platform_portability_qualified=False, cases={})
if IOS.is_file():
    report['ios_static'] = binary_identity(IOS)
    report['host_ios_build_uuid_differ'] = report['host']['macho_uuid'] != report['ios_static']['macho_uuid']
with tempfile.TemporaryDirectory(prefix='pipeline-cache-', dir=OUT) as temporary:
    for mode in ['produce', 'consume', 'uuid-miss', 'shader-miss']:
        run = subprocess.run([str(executable), str(LIBRARY), str(Path(temporary) / 'compute.bin'), mode],
                             env=env, text=True, capture_output=True, timeout=120)
        log = OUT / ('pipeline-cache-' + mode + '.log')
        log.write_text(run.stdout + run.stderr)
        match = re.search(r'^PASS: Turnip pipeline cache (\S+); uuid=([0-9a-f]{32}) bytes=(\d+) strict=(\d+) feedback=0x([0-9a-f]+) strict_us=([\d.]+) compile_us=([\d.]+); no shader execution$', run.stdout, re.M)
        if run.returncode or not match or match[1] != mode:
            raise SystemExit('Turnip pipeline cache %s failed; see %s' % (mode, log))
        report['cases'][mode] = dict(pipeline_cache_uuid=match[2], bytes=int(match[3]), strict_result=int(match[4]),
                                     feedback_flags=int(match[5], 16), strict_us=float(match[6]), compile_us=float(match[7]))
        print(match[0], flush=True)
(OUT / 'pipeline-cache-report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: separate-process Turnip cache hit and UUID/shader miss controls; host only, cross-platform portability unqualified')
