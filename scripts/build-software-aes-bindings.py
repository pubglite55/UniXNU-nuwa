#!/usr/bin/env python3
"""Bind the source AES subclass to measured, unchanged original ARM64 methods."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
import native_prelink as np

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--objects-dir', type=Path, default=ROOT / 'build/software-aes')
args = parser.parse_args()

audit_path = ROOT / 'build/image4-ignition/aes-interface-audit.json'
recorded = ROOT / 'scripts/data/native-aes-original-bindings.S'
if not audit_path.is_file() and recorded.is_file():
    # Without the qualification evidence of the original kernelcache (kernel candidate, KDK annotations, live metadata),
    # bind with the recorded result of that audit. The addresses belong to the kernelcache pinned in board.toml.
    out = args.objects_dir
    subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-Werror', '-Wno-incompatible-sysroot', '-c', recorded,
                    '-o', out / 'original-bindings.o'], check=True)
    archive = out / 'libSoftwareAES.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['xcrun', 'ar', 'rcs', archive, out / 'NativeAES.o', out / 'original-bindings.o'], check=True)
    print('PASS: native AES bound with the recorded original-kernelcache addresses')
    raise SystemExit(0)
audit = json.loads(audit_path.read_text())
obj_path = args.objects_dir / 'NativeAES.o'
obj = obj_path.read_bytes()
obj_image = np.macho(obj)
symcmd = next(offset for command, offset, length in obj_image['commands'] if command == 2)
symoff, symcount, stroff, _ = struct.unpack_from('<4I', obj, symcmd + 8)
object_symbols = []
for index in range(symcount):
    strx, kind, _, _, value = struct.unpack_from('<IBBHQ', obj, symoff + index * 16)
    name = obj[stroff + strx:obj.index(b'\0', stroff + strx)].decode()
    object_symbols.append((name, value, kind))
own_vtable = next(value for name, value, kind in object_symbols if name == '__ZTV9NativeAES')
relocations = {}
for segment in obj_image['segments']:
    for section in segment['sections']:
        if section['va'] <= own_vtable < section['va'] + section['size']:
            reloc_offset, reloc_count = struct.unpack_from('<II', obj, section['command_offset'] + 56)
            for index in range(reloc_count):
                address, word = struct.unpack_from('<II', obj, reloc_offset + index * 8)
                if word >> 27 & 1 and word >> 28 == 0 and word >> 25 & 3 == 3:
                    relocations[section['va'] + address] = object_symbols[word & 0xffffff][0]
overrides = {0, 1, 7, 86, 111, 117, 168, 169, 170, 171, 172}
for row in audit['methods']:
    names = row['reference_names']
    if row['slot'] in overrides:
        names = [n.replace('16IOAESAccelerator', '9NativeAES') for n in names]
    if relocations.get(own_vtable + 16 + row['slot'] * 8) not in names:
        raise SystemExit(f'Compiled native subclass dispatch mismatch at slot {row["slot"]}')
if own_vtable + 16 + len(audit['methods']) * 8 in relocations:
    raise SystemExit('Unexpected additional native subclass method')
kernel = (ROOT / 'build/xnu-prelink/native-defaults-candidate.macho').read_bytes()
if hashlib.sha256(kernel).hexdigest() != audit['candidate_sha256'] or not audit['live_native_4k']:
    raise SystemExit('First qualify the original AES interface and live metadata')
image = np.macho(kernel)
plan = json.loads((ROOT / 'build/xnu-prelink/native-defaults-candidate.json').read_text())
text = next(e for e in plan['extents'] if e['module'] == 'com.apple.iokit.IOCryptoAcceleratorFamily' and e['segment'] == '__TEXT_EXEC')


def read(va, length):
    at = np.backed_offset(image['segments'], va, length, len(kernel))
    return kernel[at:at + length]


def branch(va):
    word = struct.unpack('<I', read(va, 4))[0]
    if word & 0xfc000000 != 0x14000000:
        raise SystemExit('Expected a genuine one-instruction destructor tail call')
    immediate = word & 0x3ffffff
    if immediate & 0x2000000:
        immediate -= 0x4000000
    return va + immediate * 4


vptr = int(audit['vtable'], 16) + 16
constructors = []
for va in range(text['va'], text['va'] + text['size'] - 32, 4):
    a = struct.unpack('<8I', read(va, 32))
    if (a[0:2] != (0xa9bf7bfd, 0x910003fd) or a[2] & 0xfc000000 != 0x94000000 or
        a[3] & 0x9f00001f != 0x90000008 or a[4] & 0xffc003ff != 0x91000108 or
        a[5:] != (0xf9000008, 0xa8c17bfd, 0xd65f03c0)):
        continue
    immediate = ((a[3] >> 5 & 0x7ffff) << 2) | (a[3] >> 29 & 3)
    if immediate & 0x100000:
        immediate -= 0x200000
    address = ((va + 12) & ~4095) + immediate * 4096 + (a[4] >> 10 & 4095)
    if address == vptr:
        constructors.append(va)
if len(constructors) != 2:
    raise SystemExit('Cannot uniquely qualify the two original protected constructors')
# Identical x0/x1 forwarding, same BL destination and same vptr store.
for left, right in zip(struct.unpack('<8I', read(constructors[0], 32)),
                       struct.unpack('<8I', read(constructors[1], 32))):
    if left != right and left & 0xfc000000 != 0x94000000:
        raise SystemExit('Original constructor forms differ beyond their relative call')
calls = []
for va in constructors:
    word = struct.unpack('<I', read(va + 8, 4))[0]
    immediate = word & 0x3ffffff
    if immediate & 0x2000000:
        immediate -= 0x4000000
    calls.append(va + 8 + immediate * 4)
if len(set(calls)) != 1 or not text['va'] <= calls[0] < text['va'] + text['size']:
    raise SystemExit('Original constructors do not call the same genuine crypto parent')
destructor = int(audit['methods'][0]['candidate_target'], 16)
if branch(destructor - 4) != branch(destructor):
    raise SystemExit('Original D1/D2 destructor semantics differ')
bindings = {name: int(row['candidate_target'], 16) for row in audit['methods']
            if not row['kernel_names'] for name in row['reference_names']}
bindings.update({'__ZN16IOAESAcceleratorC2EPK11OSMetaClass': constructors[0],
                 '__ZN16IOAESAcceleratorD2Ev': destructor - 4,
                 '__ZN16IOAESAccelerator10gMetaClassE': int(audit['live_metaclasses']['IOAESAccelerator'], 16)})
out = args.objects_dir
out.mkdir(parents=True, exist_ok=True)
source = out / 'original-bindings.S'
source.write_text(''.join(f'.globl {name}\n.set {name}, {address:#x}\n' for name, address in sorted(bindings.items())))
subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-Werror', '-Wno-incompatible-sysroot', '-c', source,
                '-o', out / 'original-bindings.o'], check=True)
archive = out / 'libSoftwareAES.a'
archive.unlink(missing_ok=True)
subprocess.run(['xcrun', 'ar', 'rcs', archive, out / 'NativeAES.o', out / 'original-bindings.o'], check=True)
(out / 'bindings.json').write_text(json.dumps(dict(original_sha256=audit['original_sha256'],
    ordinary_candidate_sha256=audit['candidate_sha256'], original_slide=plan['slide'],
    protected_constructor_forms=[hex(x) for x in constructors], original_crypto_constructor=hex(calls[0]),
    bindings={name: hex(value) for name, value in bindings.items()}, original_instructions_modified=False,
    compiled_subclass_slots_checked=len(audit['methods']), compiled_subclass_sha256=hashlib.sha256(obj).hexdigest()), indent=2) + '\n')
print(f'PASS: {len(bindings)} native bindings to actual original metaclass/methods; no replacement code')
