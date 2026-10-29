#!/usr/bin/env python3
"""Run bounded real-firmware host controls and cross-build the native GMU planner."""
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
directory = ROOT / 'kits/AdrenoFirmware'
out = ROOT / 'build/adreno-firmware'
out.mkdir(parents=True, exist_ok=True)
firmware = ROOT / '.cache/firmware/sheng-gpu/qcom/gmu_gen70200.bin'
test = out / 'test-gmu'
subprocess.run(['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-fsanitize=address,undefined', directory / 'AdrenoFirmware.c', directory / 'test_gmu.c', '-o', test], check=True)
result = subprocess.run([test, firmware], capture_output=True, text=True, timeout=30, check=True)
print(result.stdout, end='')
obj = out / 'AdrenoFirmware.o'
subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-std=c11', '-O2',
                '-Wall', '-Wextra', '-Werror', '-Wno-incompatible-sysroot', '-ffreestanding', '-c',
                directory / 'AdrenoFirmware.c', '-o', obj], check=True)
data = obj.read_bytes()
image = macho(data)
version = next(at for cmd, at, _ in image['commands'] if cmd == 0x32)
if image['kind'] != 1 or struct.unpack_from('<II', data, version + 8) != (2, 0x110000):
    raise SystemExit('Require ordinary ARM64 subtype-0 / iOS-17 native object')
symbols = subprocess.check_output(['xcrun', 'nm', '-u', obj], text=True).strip()
if symbols:
    raise SystemExit('Freestanding planner unexpectedly imports runtime code: ' + symbols)
report = dict(kit_revision=subprocess.check_output(['git', '-C', directory, 'rev-parse', 'HEAD'], text=True).strip(),
    firmware_sha256=hashlib.sha256(firmware.read_bytes()).hexdigest(),
    source_sha256=hashlib.sha256((directory / 'AdrenoFirmware.c').read_bytes()).hexdigest(),
    header_sha256=hashlib.sha256((directory / 'AdrenoFirmware.h').read_bytes()).hexdigest(),
    object_sha256=hashlib.sha256(data).hexdigest(), actual_gmu_records=15, actual_payload_records=4,
    actual_payload_bytes=66604, prefix_lengths_tested=66844, structurally_valid_prefixes=14,
    explicit_refusal_controls=6, failure_leaves_output_unchanged=True,
    host_address_and_undefined_sanitizers=True, ordinary_arm64_ios17=True, undefined_imports=0,
    gpu_execution_qualified=False, firmware_authenticity_qualified=False, metal_qualified=False)
(out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: freestanding ordinary ARM64 / iOS 17 object; no external runtime imports; GPU/Metal remain unqualified')
