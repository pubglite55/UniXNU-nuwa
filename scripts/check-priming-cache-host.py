#!/usr/bin/env python3
"""Qualify real device-priming cache hits while all compilation is forbidden.

Actual Turnip/IR3 plus the mandatory software transport; no shader execution,
physical GPU, or deadline claim. Preserve exact source/driver/cache identities.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / 'drivers/AdrenoMetal'
OUT = ROOT / 'build/priming-cache'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--baseline', type=Path, help='Optional exact preserved pre-fix executable for a before/after refusal control')
parser.add_argument('--cross-build-ios', action='store_true', help='Link/sign the same instrument for iOS; never run or stage hardware')
args = parser.parse_args()
work = args.output.resolve()


def require(value, reason):
    if not value:
        raise SystemExit(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


require(not work.exists(), 'Preserve the existing controls; choose a fresh output directory')
require(shutil.disk_usage(ROOT).free > 5 * 1024**3 + 256 * 1024**2, 'Preserve 5 GiB and bounded allowance')
OUT.mkdir(exist_ok=True)
work.mkdir(parents=True)
loader, program = OUT / 'libOfflinePrimingCacheControl.dylib', OUT / 'priming_cache_host'
bridge = ROOT / 'build/adreno-metal-bridge/host/libadreno_metal_bridge.a'
driver = ROOT / 'build/mesa-tu/src/freedreno/vulkan/libvulkan_freedreno.dylib'
peer = ROOT / 'build/turnip-darwin-host/libhostiokit.dylib'
flags = ['xcrun', 'clang++', '-O1', '-std=c++17', '-Wall', '-Wextra', '-Werror']
subprocess.run([*flags, '-dynamiclib', '-I', ROOT / '.cache/mesa-work/include', KIT / 'bridge/priming_cache_loader.cpp', '-o', loader], check=True, timeout=60)
subprocess.run([*flags, KIT / 'bridge/priming_cache_host.cpp', bridge, '-Wl,-dead_strip', '-Wl,-S',
                '-framework', 'Foundation', '-framework', 'CoreFoundation', '-framework', 'IOKit', '-o', program], check=True, timeout=90)
ios_link = None
if args.cross_build_ios:
    import plistlib
    import struct
    target = OUT / 'ios'
    target.mkdir(exist_ok=True)
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True, timeout=10).strip()
    ios_bridge = ROOT / 'build/adreno-metal-bridge/ios/libadreno_metal_bridge.a'
    peer_dir = ROOT / 'build/turnip-ios-compiler-peer'
    ios_peer = peer_dir / 'libOfflineTurnipCompilerPeer.dylib'
    peer_build = json.loads((peer_dir / 'build-report.json').read_text())
    require(sha(ios_peer) == peer_build['outputs'][ios_peer.name]['sha256'], 'Exact own signed software peer')
    for name, digest in peer_build['sources'].items():
        require(sha(ROOT / name) == digest, 'Exact software peer source: ' + name)
    policy = peer_dir / 'compiler-entitlements.plist'
    require(plistlib.loads(policy.read_bytes()) == {'com.apple.private.security.no-container': True,
            'com.apple.private.bindfs-allow': True}, 'Exact own offline permissions; no no-sandbox')
    ios_flags = [*flags, '-target', 'arm64-apple-ios17.0', '-isysroot', sdk, '-fstack-protector-strong']
    ios_loader, worker = target / loader.name, target / 'compiler-worker'
    subprocess.run([*ios_flags, '-dynamiclib', '-install_name', '@rpath/' + loader.name, '-I', ROOT / '.cache/mesa-work/include',
                    KIT / 'bridge/priming_cache_loader.cpp', '-o', ios_loader], check=True, timeout=60)
    subprocess.run([*ios_flags, KIT / 'bridge/priming_cache_host.cpp', ios_bridge, '-Wl,-dead_strip', '-Wl,-S',
                    '-Wl,-needed_library,' + str(ios_peer), '-Wl,-rpath,/System/Library/Extensions/OfflineTurnipCompiler',
                    '-framework', 'Foundation', '-framework', 'CoreFoundation', '-framework', 'IOKit', '-o', worker], check=True, timeout=120)
    outputs = {}
    for path in [ios_loader, worker]:
        command = ['codesign', '--force', '--sign', '-', '--pagesize', '4096', '--identifier', 'org.blu-sharky.offline-priming-cache.' + path.stem]
        if path == worker:
            command += ['--entitlements', str(policy)]
        subprocess.run([*command, str(path)], check=True, timeout=30)
        subprocess.run(['codesign', '--verify', '--strict', str(path)], check=True, capture_output=True, timeout=30)
        detail = subprocess.run(['codesign', '--display', '--verbose=4', str(path)], capture_output=True, text=True, check=True, timeout=30).stderr
        cdhash = re.search(r'^CDHash=([a-f0-9]{40})$', detail, re.M)
        raw = path.read_bytes()
        require(struct.unpack_from('<3I', raw) == (0xfeedfacf, 0x100000c, 0) and cdhash and re.search(r'^Page size=4096$', detail, re.M),
                'Actual own ordinary ARM64 4K CodeDirectory')
        cursor, builds, ids = 32, [], []
        for _ in range(struct.unpack_from('<I', raw, 16)[0]):
            command, size = struct.unpack_from('<2I', raw, cursor)
            require(size >= 8 and cursor + size <= len(raw), 'Bounded actual Mach-O')
            if command == 0x32:
                builds.append(struct.unpack_from('<2I', raw, cursor + 8))
            if command == 0x1b:
                ids.append(raw[cursor + 8:cursor + 24].hex())
            cursor += size
        require(builds == [(2, 0x110000)] and len(ids) == 1, 'Actual iOS17 build/UUID')
        outputs[path.name] = dict(sha256=sha(path), bytes=len(raw), cdhash=cdhash[1], macho_uuid=ids[0], platform=2, cpu_subtype=0, signature_page_bytes=4096)
    ios_link = dict(evidence='cross-link/signature verification only, not iOS execution', outputs=outputs,
                   bridge_sha256=sha(ios_bridge), peer_sha256=sha(ios_peer), peer_report_sha256=sha(peer_dir / 'build-report.json'))
env = {k: v for k, v in os.environ.items() if not k.startswith(('IR3_', 'FD_MESA_', 'NIR_', 'TU_', 'HOSTSIM_', 'MESA_', 'NMB_TEST_'))}
env.update(DYLD_INSERT_LIBRARIES=str(peer), NMB_TEST_PRIMING_CACHE_LOADER=str(loader))
cache = work / 'control.cache'
pattern = re.compile(r'^PASS: device priming (\S+) pid=(\d+) compute=(\d+)/(\d+)/(\d+)/(\d+)/(\d+) graphics=(\d+)/(\d+)/(\d+)/(\d+)/(\d+) uuid_mutations=(\d+) submissions=(\d+) live=0; software peer, no shader execution$', re.M)
fields = ['pid', 'compute_calls', 'compute_success', 'compute_required', 'compute_valid', 'compute_hits',
          'graphics_calls', 'graphics_success', 'graphics_required', 'graphics_valid', 'graphics_hits', 'uuid_mutations', 'submissions']
cases = {}


def case(label, mode, directory):
    run = subprocess.run([str(program), str(driver), str(directory), mode], env=env, capture_output=True, text=True, timeout=60)
    log = work / (label + '.log')
    log.write_text(run.stdout + run.stderr)
    row = pattern.search(run.stdout)
    require(run.returncode == 0 and row and row[1] == mode, 'Actual priming control failed: ' + label)
    data = dict(zip(fields, map(int, row.groups()[1:])))
    require(data['submissions'] == 1 and data['compute_calls'] == 1, 'Full priming still submits its barriers; observed non-generated compute shape')
    if mode in ('cold-miss', 'uuid-miss'):
        require(data['compute_success'] == 0 and data['compute_required'] == 1 and data['graphics_calls'] == 0,
                'Actual cold/invalid priming fails instead of silently compiling')
        if mode == 'uuid-miss':
            require(data['uuid_mutations'] > 0, 'Actual driver cache UUID refusal control')
    else:
        require(data['compute_success'] == data['compute_valid'] == data['graphics_calls'] == data['graphics_success'] == data['graphics_valid'] == 1,
                'Both actual helper creations and their feedback are valid')
        if mode == 'consume':
            require(data['compute_hits'] == data['graphics_hits'] == 1 and data['compute_required'] == data['graphics_required'] == 0,
                    'Both helpers truly hit with compilation forbidden')
    data['log_sha256'] = sha(log)
    cases[label] = data
    print(row[0], flush=True)


case('cold-miss', 'cold-miss', cache)
case('produce', 'produce', cache)
records = [p for p in cache.rglob('*') if p.is_file()]
require(len(records) == 1 and records[0].stat().st_size < 16 * 1024**2, 'Exactly one bounded native priming record')
record = records[0]
original = record.read_bytes()
require(original.startswith(b'M2VPPLC\0') and hashlib.sha256(original[:-32]).digest() == original[-32:], 'Actual driver record and checksum')
case('consume', 'consume', cache)
case('uuid-miss', 'uuid-miss', cache)
require(record.read_bytes() == original, 'Warm and UUID controls preserve producer record bytes')
for label in ['truncated-miss', 'checksum-miss']:
    directory = work / (label + '.cache')
    shutil.copytree(cache, directory)
    bad = directory / record.relative_to(cache)
    if label == 'truncated-miss':
        bad.write_bytes(original[:20])
    else:
        data = bytearray(original);data[-33] ^= 1;bad.write_bytes(data)
    case(label, 'cold-miss', directory)
require(len({v['pid'] for v in cases.values()}) == len(cases), 'Independent cold processes for all controls')
baseline_evidence = None
if args.baseline:
    baseline = args.baseline.resolve()
    baseline_report = ROOT / 'build/ui-shader-coverage/turnip-graphics/committed-qualified/checkpoint.json'
    old = json.loads(baseline_report.read_text())
    require(baseline.is_file() and sha(baseline) == old['process']['sha256'], 'Exact previously qualified executable with uncached priming')
    old_env = dict(env, NMB_TEST_GRAPHICS_CACHE_LOADER=str(loader), NMB_TEST_FORCE_PRIME_STRICT='1')
    run = subprocess.run([str(baseline), str(driver), str(work / 'control'), 'consume'], env=old_env, capture_output=True, text=True, timeout=60)
    log = work / 'baseline.log'
    log.write_text(run.stdout + run.stderr)
    require(run.returncode != 0 and 'device: Vulkan(VkResultCode(1000297000))' in log.read_text(),
            'Old executable must still fail during device open, using this exact populated cache directory')
    require(record.read_bytes() == original, 'The old refusal also preserves all producer record bytes')
    baseline_evidence = dict(process_sha256=sha(baseline), log_sha256=sha(log), exit_code=run.returncode)
patches = KIT / 'bridge/patches'
report = dict(evidence='real host Turnip compiler, mandatory software peer; no shader execution', checker_sha256=sha(Path(__file__)),
    sources_sha256={str(p.relative_to(ROOT)): sha(p) for p in [KIT / 'bridge/priming_cache_host.cpp', KIT / 'bridge/priming_cache_loader.cpp', KIT / 'bridge/graphics_cache_loader.cpp']},
    runtime_base_revision=subprocess.check_output(['git', '-C', str(ROOT / '.cache/gpu-reference/metal2vulkan'), 'rev-parse', 'HEAD'], text=True).strip(),
    runtime_patches_sha256={p.name: sha(p) for p in sorted(patches.glob('*.patch'))}, host_bridge_sha256=sha(bridge),
    driver_sha256=sha(driver), peer_sha256=sha(peer), ios_cross_link=ios_link, process_sha256=sha(program), loader_sha256=sha(loader),
    cache_record_path=str(record.relative_to(cache)), cache_record_sha256=sha(record), cache_record_bytes=len(original),
    driver_cache_uuid=original[20:36].hex(), cases=cases, baseline=baseline_evidence,
    exit_guard_priming_preserved=True, generated_command_priming_qualified=False, ios_execution=False, shader_execution=False,
    physical_device_tested=False, active_native_adreno_4k=False, complete_ui_variant_coverage=False, hardware_ready=False, stable_120_fps_qualified=False)
(work / 'checkpoint.json').write_text(json.dumps(report, indent=2) + '\n')
(OUT / 'checkpoint.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: both priming helpers hit with compilation forbidden; invalid data refuses and leaves no live software objects')
if baseline_evidence:
    print('PASS: preserved pre-fix executable still fails in device open with the same populated cache')
