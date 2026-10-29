#!/usr/bin/env python3
"""Qualify native PM4 structure handling; this is not a GPU execution test."""
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
kit = ROOT / 'kits/AdrenoPM4'
out = ROOT / 'build/adreno-pm4'
out.mkdir(parents=True, exist_ok=True)
test = out / 'test-pm4'
subprocess.run(['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-fsanitize=address,undefined', kit / 'AdrenoPM4.c', kit / 'test_pm4.c', '-o', test], check=True)
result = subprocess.run([test], capture_output=True, text=True, timeout=30, check=True)
print(result.stdout, end='')
obj = out / 'AdrenoPM4.o'
subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-std=c11', '-O2',
                '-Wall', '-Wextra', '-Werror', '-Wno-incompatible-sysroot', '-ffreestanding', '-c',
                kit / 'AdrenoPM4.c', '-o', obj], check=True)
data = obj.read_bytes()
image = macho(data)
version = next(at for cmd, at, _ in image['commands'] if cmd == 0x32)
if image['kind'] != 1 or struct.unpack_from('<II', data, version + 8) != (2, 0x110000):
    raise SystemExit('Require ordinary ARM64 subtype-0 / iOS-17 native object')
imports = subprocess.check_output(['xcrun', 'nm', '-u', obj], text=True).strip()
if imports:
    raise SystemExit('Freestanding PM4 unexpectedly imports runtime code: ' + imports)
report = dict(source_sha256=hashlib.sha256((kit / 'AdrenoPM4.c').read_bytes()).hexdigest(),
    header_sha256=hashlib.sha256((kit / 'AdrenoPM4.h').read_bytes()).hexdigest(),
    object_sha256=hashlib.sha256(data).hexdigest(), type7_pairs=2097152,
    register_indices=262144, register_counts=127, single_bit_refusals=12256,
    failure_leaves_output_unchanged=True, host_address_and_undefined_sanitizers=True,
    ordinary_arm64_ios17=True, undefined_imports=0,
    structural_only=True, submission_authorized=False,
    gpu_execution_qualified=False, metal_qualified=False)
(out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: freestanding ordinary ARM64 / iOS 17 object, no runtime imports; no GPU/Metal execution claim')
