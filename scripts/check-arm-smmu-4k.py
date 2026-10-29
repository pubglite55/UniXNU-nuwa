#!/usr/bin/env python3
"""Qualify inactive native 4K SMMU tables; this is not a GPU execution test."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import macho

subprocess.run([sys.executable, ROOT / 'scripts/fetch-adreno-inputs.py'], check=True)
kit = ROOT / 'kits/ArmSmmu4K'
out = ROOT / 'build/arm-smmu-4k'
out.mkdir(parents=True, exist_ok=True)
test = out / 'test-tables'
subprocess.run(['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-fsanitize=address,undefined', kit / 'ArmSmmu4K.c', kit / 'test_tables.c', '-o', test], check=True)
result = subprocess.run([test], capture_output=True, text=True, timeout=30, check=True)
print(result.stdout, end='')
obj = out / 'ArmSmmu4K.o'
subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-std=c11', '-O2',
                '-Wall', '-Wextra', '-Werror', '-Wno-incompatible-sysroot', '-ffreestanding', '-c',
                kit / 'ArmSmmu4K.c', '-o', obj], check=True)
data = obj.read_bytes()
image = macho(data)
version = next(at for cmd, at, _ in image['commands'] if cmd == 0x32)
if image['kind'] != 1 or struct.unpack_from('<II', data, version + 8) != (2, 0x110000):
    raise SystemExit('Require ordinary ARM64 subtype-0 / iOS-17 native object')
imports = subprocess.check_output(['xcrun', 'nm', '-u', obj], text=True).strip()
if set(imports.split()) != {'___stack_chk_fail', '___stack_chk_guard'}:
    raise SystemExit('Unexpected imports; retain the native stack protector: ' + imports)
report = dict(source_sha256=hashlib.sha256((kit / 'ArmSmmu4K.c').read_bytes()).hexdigest(),
    header_sha256=hashlib.sha256((kit / 'ArmSmmu4K.h').read_bytes()).hexdigest(),
    object_sha256=hashlib.sha256(data).hexdigest(), input_widths=list(range(32, 49)),
    output_widths=[32, 36, 40, 42, 44, 48], native_granule_bytes=4096,
    leaf_bytes=4096, block_leaves=False, independent_graph_and_walk=True,
    explicit_shareability=[2, 3], conflicting_shareability_aliases_refused=True,
    failure_leaves_tables_unchanged=True, host_address_and_undefined_sanitizers=True,
    ordinary_arm64_ios17=True, undefined_imports=sorted(imports.split()),
    actual_smmu_state_observed=False, tables_activated=False,
    gpu_execution_qualified=False, metal_qualified=False)
(out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: ordinary ARM64 / iOS 17 inactive 4K tables, stack protector retained; no live SMMU/GPU qualification')
