#!/usr/bin/env python3
"""Bind the concrete block driver to the qualified original ordinary iOS class."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
import native_prelink as np
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--component', choices=['VirtioMmioBlock', 'RamBlock', 'NativeVirtioBlock', 'NativeRamBlock'], default='VirtioMmioBlock')
parser.add_argument('--directory', type=Path, default=ROOT / 'build/virtio-mmio-block')
args = parser.parse_args()
out = args.directory.resolve()
audit = json.loads((ROOT / 'build/storage-abi/interface-audit.json').read_text())
canonical = {'NativeVirtioBlock': 'VirtioMmioBlock', 'NativeRamBlock': 'RamBlock'}.get(args.component, args.component)
component = {'VirtioMmioBlock': 'NativeVirtioBlock', 'RamBlock': 'NativeRamBlock'}[canonical]
mangled = str(len(component)) + component
obj_path = out / (component + '.o')
obj = obj_path.read_bytes()
image = np.macho(obj)
if not audit['live_native_4k'] or audit['method_slots'] != 190 or not audit['abstract_complete_destructors_trap']:
    raise SystemExit('First qualify original live storage metadata and its real base functions')
offset = next(at for cmd, at, size in image['commands'] if cmd == 2)
sy, count, st, _ = struct.unpack_from('<4I', obj, offset + 8)
symbols = []
for i in range(count):
    ix, kind, _, _, value = struct.unpack_from('<IBBHQ', obj, sy + i * 16)
    symbols.append((obj[st + ix:obj.index(b'\0', st + ix)].decode(), value, kind))
vtable = next(v for name, v, kind in symbols if name == '__ZTV' + mangled)
relocations = {}
for segment in image['segments']:
    for section in segment['sections']:
        if section['va'] <= vtable < section['va'] + section['size']:
            ro, rc = struct.unpack_from('<II', obj, section['command_offset'] + 56)
            for i in range(rc):
                address, word = struct.unpack_from('<II', obj, ro + i * 8)
                if word >> 27 & 1 and word >> 28 == 0 and word >> 25 & 3 == 3:
                    relocations[section['va'] + address] = symbols[word & 0xffffff][0]
compiled = [relocations.get(vtable + 16 + i * 8) for i in range(190)]
if not all(compiled) or vtable + 16 + 190 * 8 in relocations or '___cxa_pure_virtual' in compiled:
    raise SystemExit('Concrete block class has missing/additional/pure virtual methods')
all_names = list(dict.fromkeys(compiled + [r['reference_name'] for r in audit['methods']]))
demangled = subprocess.check_output(['xcrun', 'c++filt'], input='\n'.join(n[1:] for n in all_names) + '\n', text=True).splitlines()
readable = dict(zip(all_names, demangled))
overrides = 0
for row, actual in zip(audit['methods'], compiled):
    expected = row['reference_name']
    own = actual.startswith(('__ZN' + mangled, '__ZNK' + mangled))
    if expected == '___cxa_pure_virtual':
        if not own:
            raise SystemExit('A required transport operation is not implemented')
    elif actual != expected:
        if not own or (row['slot'] not in (0, 1) and readable[actual].split('::', 1)[1] != readable[expected].split('::', 1)[1]):
            raise SystemExit('Concrete subclass dispatch mismatch at slot ' + str(row['slot']))
    overrides += own
kernel_path = ROOT / 'build/xnu-prelink/native-apfs-load-positive.macho'
# The binding values come from the recorded audit; the candidate only proves the audit's identity. Build products are pruned, so a
# missing candidate is accepted (the audit JSON is the pinned record) while a present one must still match.
if kernel_path.exists() and hashlib.sha256(kernel_path.read_bytes()).hexdigest() != audit['candidate_sha256']:
    raise SystemExit('Original binding input identity changed')
possible = {r['reference_name']: int(r['candidate_target'], 16) for r in audit['methods'] if not r['kernel_names']}
possible.update({'__ZN20IOBlockStorageDeviceC2EPK11OSMetaClass': int(audit['original_protected_constructor'], 16),
                 '__ZN20IOBlockStorageDeviceD2Ev': int(audit['original_base_destructor'], 16),
                 '__ZN20IOBlockStorageDevice10gMetaClassE': int(audit['original_metaclass'], 16),
                 '__ZTV20IOBlockStorageDevice': int(audit['vtable'], 16)})
undefined = [name for name, value, kind in symbols if kind == 1 and ('IOBlockStorageDevice' in name)]
if any(name not in possible for name in undefined):
    raise SystemExit('Unqualified original storage import')
# Abstract D1/D0 are BRK traps. Only actual base D2 is appropriate for this subclass.
if any(re.search(r'IOBlockStorageDeviceD[01]Ev$', n) for n in undefined):
    raise SystemExit('Concrete driver must not invoke abstract complete/deleting destruction')
bindings = {name: possible[name] for name in undefined}
assembly = out / 'original-bindings.S'
assembly.write_text(''.join(f'.globl {name}\n.set {name}, {value:#x}\n' for name, value in sorted(bindings.items())))
subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-Werror', '-Wno-incompatible-sysroot',
                '-c', assembly, '-o', out / 'original-bindings.o'], check=True)
archive = out / ('lib' + canonical + '.a')
archive.unlink(missing_ok=True)
subprocess.run(['xcrun', 'ar', 'rcs', archive, obj_path, out / 'original-bindings.o'], check=True)
(out / 'bindings.json').write_text(json.dumps(dict(original_candidate_sha256=audit['candidate_sha256'],
    compiled_object_sha256=hashlib.sha256(obj).hexdigest(), virtual_methods_checked=190,
    concrete_overrides=overrides, unresolved_original_imports=0,
    bindings={name: hex(value) for name, value in bindings.items()}, original_code_modified=False,
    actual_io_qualified=False), indent=2) + '\n')
print(f'PASS: 190 concrete slots, {overrides} overrides and {len(bindings)} genuine original storage imports')
print('Actual device I/O and filesystem integration remain unqualified by this compile/ABI audit.')
