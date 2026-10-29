#!/usr/bin/env python3
"""Bounded original AIR -> NIR -> IR3 host qualification; no GPU device access."""
import concurrent.futures
import ctypes
import hashlib
import json
import os
from pathlib import Path
import random
import re
import urllib.request
import shutil
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'build/air-nir'
MESA = ROOT / 'build/mesa-ir3'
KIT = ROOT / 'kits/AirNir'
CHIP = '0x43050a01'  # board source/catalog identity; no hardware read
llvm_config = os.environ.get('LLVM_CONFIG') or shutil.which('llvm-config')
if not llvm_config and shutil.which('brew'):
    prefix = subprocess.check_output(['brew', '--prefix', 'llvm'], text=True, timeout=10).strip()
    llvm_config = str(Path(prefix) / 'bin/llvm-config')
if not llvm_config:
    raise SystemExit('Set LLVM_CONFIG to the qualified LLVM 23.1.3 config executable')
LLVM = Path(llvm_config)
ENV = {k: v for k, v in os.environ.items() if not k.startswith(('IR3_', 'FD_MESA_', 'NIR_', 'MESA_SHADER_'))}
ENV['PATH'] = str(ROOT / '.cache/mesa-tools/bin') + ':' + str(ROOT / '.cache/mesa-venv/bin') + ':' + ENV['PATH']
ENV['IR3_SHADER_DEBUG'] = 'asmroundtrip'


def run(command, *, timeout=30, ok=0, env=ENV):
    p = subprocess.run([str(x) for x in command], env=env, capture_output=True, text=True, timeout=timeout)
    if p.returncode != ok:
        raise RuntimeError(f'Expected status {ok}, got {p.returncode}: {command[0]}\n{p.stdout[-2000:]}\n{p.stderr[-3000:]}')
    return p


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


if run([LLVM, '--version']).stdout.strip() != '23.1.3':
    raise SystemExit('This frontend is qualified only with LLVM 23.1.3')
llvm_bin = Path(run([LLVM, '--bindir']).stdout.strip())
pins = json.loads((ROOT / 'scripts/data/adreno-compiler-inputs.json').read_text())
reference = pins['integer_fma_reference']
reference_root = ROOT / '.cache/softfloat-source'
for name, expected in reference['files'].items():
    path = reference_root / name
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        url = reference['repository'].replace('github.com', 'raw.githubusercontent.com') + '/' + reference['commit'] + '/' + name
        with urllib.request.urlopen(url, timeout=20) as stream:
            path.write_bytes(stream.read(1024 * 1024))
    if sha(path) != expected:
        raise RuntimeError('Pinned SoftFloat algorithm reference differs: ' + name)
if sha(KIT / 'licenses/SoftFloat-3e.txt') != reference['files']['COPYING.txt']:
    raise RuntimeError('Full upstream SoftFloat license must be retained')
# The base builder verifies every Mesa source change against recorded patches,
# enables full NIR, disables runtime render drivers, and qualifies real IR3.
run([sys.executable, ROOT / 'scripts/build-adreno-compiler-host.py', '--probe'], timeout=600)
run([ROOT / '.cache/mesa-venv/bin/meson', 'configure', MESA,
     '-Doffline-air-nir-dir=' + str(KIT), '-Doffline-air-nir-llvm-config=' + str(LLVM)])
build = run(['ninja', '-C', MESA, '-j4', 'src/freedreno/ir3/air_nir'], timeout=180)
(ROOT / '.cache/air-nir-build.log').write_text(build.stdout + build.stderr)
exe = MESA / 'src/freedreno/ir3/air_nir'
OUT.mkdir(parents=True, exist_ok=True)
audit = json.loads((ROOT / 'build/gpu-analysis/air/target-inputs.json').read_text())
modules = {(m['library'], m['index']): m for m in audit['modules']}
if len(modules) != 240:
    raise SystemExit('The expected original library inventory must contain exactly 240 modules')


def source(library, index):
    path = ROOT / f'build/gpu-analysis/air/{library}/module-{index}.bc'
    if sha(path) != modules[(library, index)]['bitcode_sha256']:
        raise RuntimeError('Original AIR input differs from audited library member')
    return path


results = []
fixtures = [('QuartzCore', 111, 0, 4, True), ('RenderBox', 0, 84, 6, True),
            ('RenderBox', 2, 56, 6, True), ('RenderBox', 26, 28, 4, True),
            ('RenderBox', 28, 60, 6, True), ('RenderBox', 45, 56, 6, True),
            ('RenderBox', 65, 88, 6, True), ('RenderBox', 71, 56, 6, True)]
for library, index, size, channel_count, compiled in fixtures:
    src = source(library, index)
    prefix = OUT / f'{library}-{index}'
    # Clean this known prefix so old products cannot satisfy a new refusal.
    for suffix in ('.bin', '.asm', '.nir', '.eval'):
        prefix.with_suffix(suffix).unlink(missing_ok=True)
    rng = random.Random(20261016)
    cases = []
    count = 65536 if size == 0 else 4096
    for i in range(count):
        vertex = i if size == 0 else ([0, 1, 2, 3, 4, 65535, 65536, 65537, 0xffffffff][i] if i < 9 else rng.getrandbits(32))
        values = [rng.uniform(-32, 32) for _ in range(size // 4)]
        if values:
            values[6] = rng.uniform(0, 100)  # finite, nonsingular depth/(depth+1)
        cases.append((vertex, struct.pack('<' + 'f' * len(values), *values)))
    case_path = prefix.with_suffix('.cases')
    case_path.write_bytes(b''.join(struct.pack('<I', v) + data for v, data in cases))
    p = run([exe, src, CHIP, prefix, '--compile', '--test-evaluate-int32', case_path], ok=0 if compiled else 5)
    if compiled:
        metadata = json.loads(p.stdout)
        binary_size = prefix.with_suffix('.bin').stat().st_size
        if (metadata['binary_bytes'] != binary_size or binary_size < metadata['code_dwords'] * 4 or
                metadata['code_dwords'] < 1 or binary_size > 1024 * 1024 or
                not metadata['asm_roundtrip'] or metadata['gpu_executed']):
            raise RuntimeError('Original vertex backend result differs')
        if library == 'QuartzCore' and (binary_size != 128 or sha(prefix.with_suffix('.bin')) !=
                '183870069979673265622eb249a9a540422c650464b247f0ec248ce2555480ad'):
            raise RuntimeError('Previously qualified original AIR generated code differs')
        assembly = prefix.with_suffix('.asm').read_text()
        for token in ('SYSTEM_VALUE_VERTEX_ID', 'VARYING_SLOT_POS'):
            if token not in assembly:
                raise RuntimeError('Original AIR generated code lacks expected data flow')
    else:
        raise RuntimeError('All eight selected originals must compile')
    # Independent original-IR oracle: clone original module, adapt only host
    # entry ABI/triple and replace the named AIR FMA with LLVM fused FMA.
    oracle_bc = Path(str(prefix) + '.oracle.bc')
    oracle_lib = Path(str(prefix) + '.dylib')
    run([exe, src, CHIP, oracle_bc, '--test-oracle'])
    run([llvm_bin / 'clang', '-dynamiclib', '-O0', oracle_bc, '-o', oracle_lib])
    library_handle = ctypes.CDLL(str(oracle_lib))
    oracle = library_handle.air_test_oracle
    oracle.argtypes = [ctypes.c_void_p, ctypes.c_uint16, ctypes.POINTER(ctypes.c_float)]
    oracle.restype = None
    actual = prefix.with_suffix('.eval').read_bytes()
    stride = ((channel_count + 3) // 4) * 16
    if len(actual) != count * stride:
        raise RuntimeError('Missing/extra numeric test records')
    channels = range(channel_count)
    for i, (vertex, data) in enumerate(cases):
        output = (ctypes.c_float * 8)()
        buffer = ctypes.create_string_buffer(data or b'\0')
        oracle(buffer, vertex & 65535, output)
        got = struct.unpack_from('<' + 'f' * (stride // 4), actual, i * stride)
        # Exact equality on these finite test values, including fused FMA
        # cancellation behavior. This does not evaluate generated Adreno ISA.
        if any(struct.pack('<f', got[j]) != struct.pack('<f', output[j]) for j in channels):
            raise RuntimeError(f'Original IR vs lowered NIR mismatch: {library} {index}, case {i}')
    result = dict(library=library, index=index, name=modules[(library, index)]['name'],
                  input_sha256=sha(src), cases=count, compared_channels=len(channels),
                  exact_f32_equal=True, nir_sha256=sha(prefix.with_suffix('.nir')),
                  machine_code_exported=compiled, gpu_executed=False)
    if compiled:
        instruction_count = re.search(r'prog .*?: (\d+) instr', assembly)
        if not instruction_count:
            raise RuntimeError('Missing instruction cost report')
        result.update(binary_sha256=sha(prefix.with_suffix('.bin')), binary_bytes=binary_size,
                      main_instructions=int(instruction_count.group(1)), numeric_nir_stage='after integer lowering',
                      assembly_sha256=sha(prefix.with_suffix('.asm')), asm_roundtrip=True)
    else:
        result['refusal'] = 'Strong fused FMA lacks a qualified A740 lowering; no unfused MAD substitution'
    results.append(result)
    print(f'PASS: {library} {index}: {count} original-IR/NIR cases; ' + ('A740 code + roundtrip' if compiled else 'strong-FMA export refused'), flush=True)

run([sys.executable, ROOT/'scripts/check-air-resource-inputs.py', '--compiler', exe,
     '--llvm-bindir', llvm_bin], timeout=60)
resource_report=json.loads((OUT/'resources/report.json').read_text())

run([sys.executable, ROOT/'scripts/check-air-fragment-outputs.py', '--compiler', exe,
     '--llvm-bindir', llvm_bin], timeout=30)
fragment_report=json.loads((OUT/'fragments/report.json').read_text())
run([sys.executable, ROOT/'scripts/check-air-fragment-inputs.py', '--compiler', exe,
     '--llvm-bindir', llvm_bin], timeout=60)
fragment_input_report=json.loads((OUT/'fragment-inputs/report.json').read_text())

# Full library coverage: every unsupported original input must refuse cleanly,
# without a backend assertion, a silent success or leftover machine code.
def coverage(item):
    library, index = item
    src = source(library, index)
    prefix = OUT / 'coverage' / f'{library}-{index}'
    prefix.with_suffix('.bin').unlink(missing_ok=True)
    p = subprocess.run([str(exe), str(src), CHIP, str(prefix), '--compile'], env=ENV,
                       capture_output=True, text=True, timeout=5)
    if p.returncode not in (0, 4, 5) or (p.returncode and prefix.with_suffix('.bin').exists()):
        raise RuntimeError(f'Original module did not compile/refuse cleanly: {library}/{index}: {p.stderr[-300:]}')
    reason = p.stderr.strip().splitlines()[-1] if p.stderr.strip() else 'compiled'
    return dict(library=library, index=index, exit_code=p.returncode, result=reason)


(OUT / 'coverage').mkdir(exist_ok=True)
start = time.monotonic()
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    coverage_results = list(pool.map(coverage, sorted(modules)))
if time.monotonic() - start > 30:
    raise RuntimeError('Coverage exceeded the bounded 30-second host test window')
successes = [(r['library'], r['index']) for r in coverage_results if r['exit_code'] == 0]
frontend_only = [(r['library'], r['index']) for r in coverage_results if r['exit_code'] == 5]
if frontend_only:
    raise RuntimeError('Frontend-only coverage or refusal reason differs')
expected_successes = sorted([(library,index) for library,index,*_ in fixtures] +
                            [(r['library'],r['index']) for r in resource_report['originals']+fragment_report['originals']+fragment_input_report['originals']])
if successes != expected_successes:
    raise RuntimeError('Original library compiler coverage changed; qualify every new success')

# Mutate ignored copies of the original IR for meaningful refusal controls;
# original target inputs and reference files stay unchanged.
qc = source('QuartzCore', 111).with_suffix('.ll').read_text()
rb = source('RenderBox', 0).with_suffix('.ll').read_text()
mutations = {
    'wrong-triple': qc.replace('air64-apple-ios17.7.0', 'arm64-apple-ios17.7.0'),
    'strict-float-options': qc.replace('air.compile.denorms_disable', 'air.compile.denorms_enable'),
    'strict-division': rb.replace('fdiv fast float', 'fdiv float'),
    'wrong-air-version': qc.replace('!10 = !{i32 2, i32 6, i32 0}', '!10 = !{i32 2, i32 7, i32 0}'),
    'missing-output-metadata': qc.replace('!17 = !{!"air.position", !"air.arg_type_name", !"float4"}', '!17 = !{}'),
    'unsupported-op': qc.replace('%3 = and i32 %2, 1', '%3 = xor i32 %2, 1'),
    'undefined-output': qc.replace('ret <4 x float> %10', 'ret <4 x float> poison'),
    'wrong-argument-kind': qc.replace('!"air.vertex_id"', '!"air.instance_id"'),
    'dynamic-gep': rb.replace('i64 0, i64 0\n  %4 = load', 'i64 0, i16 %1\n  %4 = load', 1),
    'out-of-range-gep': rb.replace('i64 0, i64 0\n  %4 = load', 'i64 0, i64 100\n  %4 = load', 1),
    'volatile-load': rb.replace('%4 = load float', '%4 = load volatile float', 1),
    'unknown-intrinsic': rb.replace('air.fma.v2f32', 'air.unknown.v2f32'),
}
negative = []
for name, text in mutations.items():
    if text in (qc, rb):
        raise RuntimeError('Refusal mutation did not change its source: ' + name)
    ll, bc = OUT / (name + '.ll'), OUT / (name + '.bc')
    ll.write_text(text)
    run([llvm_bin / 'llvm-as', ll, '-o', bc])
    prefix = OUT / ('refused-' + name)
    prefix.with_suffix('.bin').unlink(missing_ok=True)
    p = run([exe, bc, CHIP, prefix, '--compile'], ok=4)
    if prefix.with_suffix('.bin').exists() or 'AIR refused:' not in p.stderr:
        raise RuntimeError('Mutation did not refuse before machine-code export: ' + name)
    negative.append(dict(name=name, exit_code=4, reason=p.stderr.strip()))
for name, chip, env in [('unknown-chip', '0xdeadbeef', ENV), ('missing-roundtrip', CHIP, dict(ENV, IR3_SHADER_DEBUG=''))]:
    prefix = OUT / ('refused-' + name)
    prefix.with_suffix('.bin').unlink(missing_ok=True)
    p = run([exe, source('QuartzCore', 111), chip, prefix, '--compile'], ok=4, env=env)
    if prefix.with_suffix('.bin').exists():
        raise RuntimeError('Target/check refusal exported code')
    negative.append(dict(name=name, exit_code=4, reason=p.stderr.strip()))
truncated = OUT / 'truncated.bc'
truncated.write_bytes(source('QuartzCore', 111).read_bytes()[:64])
p = run([exe, truncated, CHIP, OUT / 'refused-truncated', '--compile'], ok=4)
negative.append(dict(name='truncated-bitcode', exit_code=4, reason=p.stderr.strip()))
run([sys.executable, KIT / 'tests/check_fma.py', '--compiler', exe,
     '--llvm-bindir', llvm_bin, '--out', OUT / 'fma', '--chip', CHIP], timeout=60)
fma_report = json.loads((OUT / 'fma/report.json').read_text())
run([sys.executable, KIT / 'tests/check_coefficients.py', '--compiler', exe,
     '--llvm-bindir', llvm_bin, '--out', OUT / 'coefficients', '--chip', CHIP], timeout=30)
coefficient_report = json.loads((OUT / 'coefficients/report.json').read_text())
run([sys.executable, KIT / 'tests/check_math_flags.py', '--compiler', exe,
     '--llvm-bindir', llvm_bin, '--out', OUT / 'math-flags', '--chip', CHIP], timeout=30)
math_flags_report = json.loads((OUT / 'math-flags/report.json').read_text())
run([sys.executable, ROOT/'scripts/check-adreno-constant-uploads.py', '--compiler', exe], timeout=60)
constant_upload_report=json.loads((OUT/'constant-uploads/report.json').read_text())
compiled_hashes={(r['library'],r['index']):r['binary_sha256'] for r in results+resource_report['originals']}
packed_hashes={(r['library'],r['index']):r['binary_sha256'] for r in constant_upload_report['original_layouts']}
if compiled_hashes != packed_hashes:
    raise RuntimeError('Shader binaries changed between numerical qualification and ABI packing')
report = dict(llvm_version='23.1.3', llvm_config_sha256=sha(LLVM), executable_sha256=sha(exe),
              kit_sources={p.name: sha(p) for p in sorted(KIT.glob('*')) if p.suffix in ('.c', '.cpp', '.h')},
              mesa_commit=json.loads((ROOT / 'scripts/data/adreno-compiler-inputs.json').read_text())['mesa']['commit'],
              chip_id=CHIP, chip_identity_source='pinned board DTS + Mesa catalog; hardware not read',
              original_cases=results, coverage=coverage_results, refusal_controls=negative,
              integer_fma_reference=reference, fused_f32_checks=fma_report,
              coefficient_fma_checks=coefficient_report, per_instruction_math_checks=math_flags_report,
              original_resource_checks=resource_report, original_fragment_checks=fragment_report,
              original_fragment_input_checks=fragment_input_report,
              constant_upload_checks=constant_upload_report,
              original_modules=240, compiled_modules=len(successes), frontend_only_modules=len(frontend_only),
              host_only=True, generated_isa_executed=False, ios_compiler_crossbuilt=False,
              metal_pipeline_linked=False, complete_library_support=False,
              test_oracle_air_fma_semantics='Explicit fused-FMA interpretation; AIR implementation equivalence remains unqualified')
(OUT / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: 240 originals classified, 15 refusal controls; 22 original shaders compiled with verified vertex/resource/fragment outputs and center-perspective inputs + real roundtrip')
print('No GPU execution, complete AIR library support, native iOS compiler or Metal/UI claim')
