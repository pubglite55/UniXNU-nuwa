#!/usr/bin/env python3
"""Bounded host qualification of real native4K leaf updates; no device access."""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import macho

kit = ROOT / 'kits/ArmSmmu4K'
out = ROOT / 'build/arm-smmu-4k-live'
out.mkdir(parents=True, exist_ok=True)
(out / 'report.json').unlink(missing_ok=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# This existing checker extracts the actual pinned Linux descriptor algorithm
# into ignored build storage. Its source validation and oracle are reused,
# rather than committing a copy of the GPL source or our own expected bits.
subprocess.run([sys.executable, ROOT / 'scripts/check-smmu4k-permissions.py'],
               check=True, timeout=60)
permission_out = ROOT / 'build/arm-smmu-4k-permissions'
permission_report = json.loads((permission_out / 'report.json').read_text())
oracle = permission_out / 'original-permissions.c'
if sha(oracle) != permission_report['oracle_sha256']:
    raise SystemExit('Original descriptor oracle identity differs')

sources = [kit / (name + '.c') for name in
           ['ArmSmmu4KContext', 'ArmSmmu4KProgram', 'ArmSmmu4KLive', 'ArmSmmu4KStreams']]
test = out / 'test-live'
subprocess.run(['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra',
                '-Werror', '-fsanitize=address,undefined', *sources,
                kit / 'test_live.c', oracle, '-o', test], check=True, timeout=60)
host = subprocess.run([test], check=True, capture_output=True, text=True, timeout=60)
print(host.stdout, end='')
counts = re.search(r'(\d+) native4K lower/upper mapping profiles, (\d+) I/O/cache/timeout/mutation failures, (\d+) physical graph mutations', host.stdout)
if not counts or int(counts[1]) != 3264:
    raise SystemExit('Expected independent profile coverage absent')
pairs = re.search(r'(\d+) dual-region native4K profiles and (\d+) dual-region failure/alias/isolation controls', host.stdout)
if not pairs or tuple(map(int,pairs.groups())) != (1632,339):
    raise SystemExit('Expected dual-region coverage absent')
batches = re.search(r'(\d+) batched scattered-page map/unmap transactions', host.stdout)
if not batches or int(batches[1]) != 174:
    raise SystemExit('Expected batched update coverage absent')
alias_test = out / 'test-alias'
subprocess.run(['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                '-DARM_SMMU4K_TEST_COVERAGE', '-fsanitize-coverage=trace-pc-guard',
                '-I', kit, kit / 'test_alias.c', *[s for s in sources if s.stem != 'ArmSmmu4KLive'], '-o', alias_test], check=True, timeout=60)
alias = subprocess.run([alias_test], check=True, capture_output=True, text=True, timeout=120)
print(alias.stdout, end='')
if not re.search(r'PASS: 15000 sorted alias checks', alias.stdout):
    raise SystemExit('Expected sorted alias coverage absent')
if 'PASS: mixed-size alias gap/long-range controls and bounded compiler-coverage work' not in alias.stdout:
    raise SystemExit('Expected bounded mixed-size alias controls absent')
(out / 'host.log').write_text(host.stdout + alias.stdout)

flags = ['-target', 'arm64-apple-ios17.0', '-O2', '-Wall', '-Wextra', '-Werror',
         '-Wno-incompatible-sysroot', '-ffreestanding', '-mgeneral-regs-only']
objects = []
imports = {}
provided = set()
for source in sources:
    obj = out / (source.stem + '.o')
    subprocess.run(['xcrun', 'clang', *flags, '-std=c11', '-c', source, '-o', obj],
                   check=True, timeout=30)
    raw = obj.read_bytes()
    info = macho(raw)
    version = next(at for command, at, _ in info['commands'] if command == 0x32)
    if (struct.unpack_from('<4I', raw) != (0xfeedfacf, 0x100000c, 0, 1)
            or struct.unpack_from('<II', raw, version + 8) != (2, 0x110000)):
        raise SystemExit('Ordinary ARM64 subtype0 / iOS17 object required')
    imports[obj.name] = subprocess.check_output(['xcrun', 'nm', '-u', obj], text=True).split()
    provided.update(line.split()[-1] for line in subprocess.check_output(
        ['xcrun', 'nm', '-gU', obj], text=True).splitlines() if line.split())
    objects.append(obj)
    analysis = subprocess.run(['xcrun', 'clang', *flags, '-std=c11', '--analyze',
                               '-Xanalyzer', '-analyzer-output=text', source,
                               '-o', out / (source.stem + '.plist')],
                              check=True, capture_output=True, text=True, timeout=30)
    if analysis.stderr.strip():
        raise SystemExit('Static analysis diagnostic: ' + analysis.stderr)
unexpected = set(sum(imports.values(), [])) - provided - {
    '___stack_chk_fail', '___stack_chk_guard', '_memcpy', '_memset'}
if unexpected:
    raise SystemExit('Unexpected runtime imports: ' + repr(unexpected))

boundary = out / 'boundary.cpp'
boundary.write_text('''#include "ArmSmmu4KLive.h"
extern "C" ArmSmmu4KStatus live_boundary(const ArmSmmu4KLiveArena *arena,
 ArmSmmu4KLiveState *state,const ArmSmmu4KIo *io,unsigned bank,
 const ArmSmmu4KContextConfig *context,const ArmSmmu4KLiveVisibility *visibility,
 const ArmSmmu4KRange *before,size_t count,const ArmSmmu4KRange *change,
 unsigned map,ArmSmmu4KLiveResult *result) {
 return ArmSmmu4KLiveUpdate(arena,state,io,bank,context,visibility,before,count,change,map,1000,result);
}
''')
consumer = out / 'boundary.o'
subprocess.run(['xcrun', 'clang++', *flags, '-std=c++17', '-I', kit, '-c',
                boundary, '-o', consumer], check=True, timeout=30)
boundary_imports = set(subprocess.check_output(['xcrun', 'nm', '-u', consumer], text=True).split())
if boundary_imports - {'___stack_chk_fail', '___stack_chk_guard'} != {'_ArmSmmu4KLiveUpdate'}:
    raise SystemExit('Actual native C++/C boundary differs')
archive = out / 'libArmSmmu4KLive.a'
subprocess.run(['xcrun', 'ar', 'rcs', archive, *objects], check=True, timeout=30)
assembly = out / 'ArmSmmu4KLive.s'
subprocess.run(['xcrun', 'clang', *flags, '-std=c11', '-S', kit / 'ArmSmmu4KLive.c', '-o', assembly],
               check=True, timeout=30)
asm = assembly.read_text()
if not re.search(r'\bstr\s+x\d+,\s*\[', asm) or not re.search(r'\bldr\s+x\d+,\s*\[', asm):
    raise SystemExit('Actual aligned native descriptor loads/stores absent')
report = dict(
    passed=True, checker_sha256=sha(Path(__file__)),
    linux_revision=permission_report['linux_revision'],
    pinned_sources=permission_report['pinned_sources'], oracle_sha256=sha(oracle),
    sources={str(p.relative_to(ROOT)): sha(p) for p in
             [*sources, *[s.with_suffix('.h') for s in sources],
              kit / 'ArmSmmu4K.h', kit / 'test_live.c']},
    host_profiles=int(counts[1]), host_failure_controls=int(counts[2]),
    host_descriptor_mutations=int(counts[3]), host_asan_ubsan=True,
    dual_region_profiles=int(pairs[1]),dual_region_failure_controls=int(pairs[2]),
    ordinary_arm64_ios17=True, general_registers_only=True, static_analysis_pass=True,
    objects={p.name: sha(p) for p in objects}, archive_sha256=sha(archive),
    undefined_imports=imports, boundary_imports=sorted(boundary_imports),
    translation_granule_bytes=4096, actual_descriptor_load_store_code=True,
    software_fixture_only=True, physical_table_ownership_qualified=False,
    hardware_cache_visibility_qualified=False, active_gpu_context_qualified=False,
    hardware_tlb_qualified=False, gpu_execution_qualified=False, gpu_fences_qualified=False)
(out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: direct native4K leaf updates, bounded real register synchronization, ARM64/iOS17 archive and C++ boundary; host fixtures only')
