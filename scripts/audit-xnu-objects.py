#!/usr/bin/env python3
"""Audit the actual XNU target objects, independent of stale compiler JSON."""
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
objects = []
failures = []
non_macho = []
for path in sorted(TARGET.rglob('*')):
    if path.suffix not in ('.o', '.cpo') or not path.is_file():
        continue
    data = path.read_bytes()
    name = str(path.relative_to(TARGET))
    if data[:4] != b'\xcf\xfa\xed\xfe':
        non_macho.append(name)
        if path.name != 'genassym.o':
            failures.append(f'{name}: unexpected non-Mach-O object')
        continue
    _, cpu, subtype, kind, count, size = struct.unpack_from('<6I', data)
    if (cpu, subtype, kind) != (0x100000c, 0, 1):
        failures.append(f'{name}: expected ordinary ARM64 MH_OBJECT')
    offset = 32
    versions = []
    for _ in range(count):
        if offset + 8 > 32 + size or 32 + size > len(data):
            raise ValueError(f'{name}: truncated load commands')
        cmd, length = struct.unpack_from('<II', data, offset)
        if length < 8 or offset + length > 32 + size:
            raise ValueError(f'{name}: invalid load command')
        if cmd == 0x32:
            platform, minimum = struct.unpack_from('<II', data, offset + 8)
            versions.append({'platform': platform, 'minimum': hex(minimum)})
            if platform != 2 or minimum != 0x110000:
                failures.append(f'{name}: expected iOS 17.0 deployment')
        offset += length
    if offset != 32 + size or not versions:
        failures.append(f'{name}: missing or inconsistent build version')
    objects.append({'path': name, 'cpu_subtype': subtype, 'versions': versions})
if not objects:
    failures.append('No target objects found')
report = {'objects': objects, 'non_macho': non_macho, 'failures': failures,
          'kernel_boot_demonstrated': False}
output = ROOT / 'build/xnu/object-audit.json'
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(report, indent=2) + '\n')
print(f'{len(objects)} target objects; {len(failures)} audit failures')
for failure in failures[:20]:
    print(failure)
raise SystemExit(bool(failures))
