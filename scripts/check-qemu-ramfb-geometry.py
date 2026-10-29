#!/usr/bin/env python3
"""Cross-check real QEMU scanout dimensions against actual native boot video."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('observation', type=Path)
parser.add_argument('--width', type=int, default=3048)
parser.add_argument('--height', type=int, default=2032)
args = parser.parse_args()
if not 1 <= args.width <= 4096 or not 1 <= args.height <= 4096:
    parser.error('Dimensions must be bounded positive values')
report = json.loads(args.observation.read_text())
video = report['actual_boot_video']
boot, pe = video['boot_args'], video['pe_video']
assert video['qemu_ramfb_attached']
assert (boot['width'], boot['height'], boot['depth']) == (args.width, args.height, 32)
assert (pe['v_width'], pe['v_height'], pe['v_depth']) == (args.width, args.height, 32)
assert boot['physical_base'] == pe['v_baseAddr'] != 0
assert boot['row_bytes'] == pe['v_rowBytes'] >= args.width * 4
capture = report['qemu_screen_capture']
png = args.observation.parent / capture['file']
data = png.read_bytes()
assert data[:8] == b'\x89PNG\r\n\x1a\n'
assert struct.unpack_from('>2I', data, 16) == (args.width, args.height)
assert hashlib.sha256(data).hexdigest() == capture['sha256']
tcr = int(report['system_registers']['TCR_EL1'], 16)
assert (tcr >> 14) & 3 == 0 and (tcr >> 30) & 3 == 2
result = dict(kernel_sha256=report['kernel_sha256'],
              evidence='actual QEMU ramfb scanout plus native boot/PE video observations',
              width=args.width, height=args.height, row_bytes=boot['row_bytes'],
              screen_sha256=capture['sha256'], native_cpu_granule_bytes=4096,
              native_legacy_display=report.get('native_legacy_display'),
              hardware_tested=False, physical_display_qualified=False)
args.observation.with_name('ramfb-geometry-checked.json').write_text(json.dumps(result, indent=2)+'\n')
print(f'PASS: actual QEMU scanout, boot_args and PE video all {args.width}x{args.height}; active CPU 4K')
