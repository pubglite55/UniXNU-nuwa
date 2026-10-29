#!/usr/bin/env python3
"""Verify the linked baseline's architecture, deployment and initial TCR."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('kernel', type=Path)
args = parser.parse_args()
data = args.kernel.read_bytes()
magic, cpu, subtype, kind, count, size = struct.unpack_from('<6I', data)
assert (magic, cpu, subtype, kind) == (0xfeedfacf, 0x100000c, 0, 2)
symbols = subprocess.check_output(['xcrun', 'nm', '-g', str(args.kernel)], text=True)
address = int(next(line.split()[0] for line in symbols.splitlines()
                   if line.split()[-1:] == ['_sysreg_restore']), 16)
offset = 32
tcr = None
deployment = None
entry = None
for _ in range(count):
    command, length = struct.unpack_from('<II', data, offset)
    assert length >= 8 and offset + length <= 32 + size <= len(data)
    if command == 0x19:
        va, _, fileoff, filesize = struct.unpack_from('<4Q', data, offset + 24)
        if va <= address and address + 8 <= va + filesize:
            tcr = struct.unpack_from('<Q', data, fileoff + address - va)[0]
    elif command == 0x32:
        deployment = struct.unpack_from('<II', data, offset + 8)
    elif command == 5:
        assert length == 288
        entry = struct.unpack_from('<Q', data, offset + 272)[0]
    offset += length
assert offset == 32 + size and entry is not None and tcr is not None
assert deployment == (2, 0x110000), deployment
assert (tcr >> 14) & 3 == 0 and (tcr >> 30) & 3 == 2, hex(tcr)
report = {'sha256': hashlib.sha256(data).hexdigest(), 'cpu_subtype': subtype,
          'deployment': 'iOS 17.0', 'entry_va': hex(entry),
          'initial_tcr': hex(tcr), 'tg0_bytes': 4096, 'tg1_bytes': 4096,
          'hardware_boot_demonstrated': False, 'os_boot_demonstrated': False}
output = Path(__file__).resolve().parents[1] / 'build/xnu/kernel-audit.json'
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
