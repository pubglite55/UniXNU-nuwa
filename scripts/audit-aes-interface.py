#!/usr/bin/env python3
"""Audit original ordinary-ARM64 AES dispatch and saved live class metadata.

The pinned ARM64e KDK file supplies symbol annotations only. It is never
linked, executed, or used as a substitute target component.
"""
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
parser.add_argument('--candidate', type=Path, default=ROOT / 'build/xnu-prelink/native-defaults-candidate.macho')
parser.add_argument('--reference', type=Path, default=ROOT / '.cache/kdk-aes-reference/System/Library/Extensions/IOCryptoAcceleratorFamily.kext/Contents/MacOS/IOCryptoAcceleratorFamily')
parser.add_argument('--snapshot', type=Path, default=ROOT / 'build/darwinboot-aes-native-metadata/gdb-stop.json')
parser.add_argument('--output', type=Path, default=ROOT / 'build/image4-ignition/aes-interface-audit.json')
args = parser.parse_args()


def require(value, message):
    if not value:
        raise SystemExit(message)


reference = args.reference.read_bytes()
ref_sha = hashlib.sha256(reference).hexdigest()
require(ref_sha == 'c487cb1e607a468e26fcc4da93a02a4d30a129360cd3ca9ca88ef3a51f8c8cd9', 'Unexpected KDK annotation input')
require(struct.unpack_from('<3I', reference) == (0xfeedfacf, 0x100000c, 0xc0000002), 'Expected reference-only ARM64e Mach-O')
segments, symbols, by_address = [], {}, {}
at = 32
for _ in range(struct.unpack_from('<I', reference, 16)[0]):
    cmd, size = struct.unpack_from('<II', reference, at)
    if cmd == 0x19:
        name, va, vm_size, fileoff, filesize = struct.unpack_from('<16s4Q', reference, at + 8)
        segments.append(dict(name=name.rstrip(b'\0').decode(), va=va, fileoff=fileoff, filesize=filesize))
    elif cmd == 2:
        symoff, count, stroff, strsize = struct.unpack_from('<4I', reference, at + 8)
    elif cmd == 0x80000034:
        fixup, _ = struct.unpack_from('<II', reference, at + 8)
    at += size
for index in range(count):
    name_index, kind, _, _, value = struct.unpack_from('<IBBHQ', reference, symoff + index * 16)
    if kind & 0xe0 or kind & 0xe != 0xe:  # Exclude zero-valued STAB duplicates.
        continue
    name = reference[stroff + name_index:reference.index(b'\0', stroff + name_index)].decode()
    symbols[name] = value
    by_address.setdefault(value, []).append(name)
_, starts, imports_offset, names_offset, import_count, import_format, names_format = struct.unpack_from('<7I', reference, fixup)
require((import_format, names_format) == (1, 0), 'Unexpected reference import encoding')
imports = []
for index in range(import_count):
    word = struct.unpack_from('<I', reference, fixup + imports_offset + index * 4)[0]
    offset = fixup + names_offset + (word >> 9)
    imports.append(reference[offset:reference.index(b'\0', offset)].decode())
# All pointer-bearing reference segments must use the qualified kernel format.
segment_count = struct.unpack_from('<I', reference, fixup + starts)[0]
for index in range(segment_count):
    offset = struct.unpack_from('<I', reference, fixup + starts + 4 + index * 4)[0]
    if offset:
        page_size, pointer_format = struct.unpack_from('<HH', reference, fixup + starts + offset + 4)
        require((page_size, pointer_format) == (4096, 7), 'Unexpected reference chained pointer format')
vtable = symbols['__ZTV16IOAESAccelerator']
end = min(value for value in by_address if value > vtable)
offset = np.backed_offset(segments, vtable, end - vtable, len(reference))
reference_slots = []
for slot in range((end - vtable) // 8 - 2):
    pointer = struct.unpack_from('<Q', reference, offset + 16 + slot * 8)[0]
    bind = bool(pointer >> 62 & 1)
    target = pointer & (0xffffffff if pointer >> 63 else (1 << 43) - 1)
    names = [imports[pointer & 0xffff]] if bind else by_address.get(target, [])
    reference_slots.append(dict(reference_slot=slot, names=names, bind=bind, target=target))
require(len(reference_slots) == 286 and not reference_slots[-1]['names'], 'Unexpected reference table boundary')
require(not any(s['va'] <= reference_slots[-1]['target'] < s['va'] + s['filesize']
                for s in segments if s['name'] == '__TEXT_EXEC'), 'Trailing reference word is executable')
require(all(r['names'] for r in reference_slots[:-1]), 'Unannotated reference method')
padding = [r for r in reference_slots[:-1] if any('_RESERVED' in n for n in r['names'])]
require(len(padding) == 104, 'Unexpected macOS reserved-slot count')
header = (ROOT / '.cache/xnu-work/libkern/libkern/c++/OSMetaClass.h').read_text()
require(re.search(r'#if !XNU_TARGET_OS_OSX\s+#define APPLE_KEXT_VTABLE_PADDING\s+0', header), 'Source iOS padding policy changed')
slots = [r for r in reference_slots[:-1] if r not in padding]
require(len(slots) == 181, 'Unexpected iOS method count')

candidate = args.candidate.read_bytes()
plan = json.loads(args.candidate.with_suffix('.json').read_text())
candidate_sha = hashlib.sha256(candidate).hexdigest()
require(candidate_sha == plan['candidate_sha256'], 'Candidate digest mismatch')
require(plan['original_sha256'] == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7', 'Unexpected target kernel provenance')
native = np.macho(candidate)  # Deliberately retains the ordinary ARM64-only gate.
exports = np.exports(candidate, native)
module = [s for s in plan['extents'] if s['module'] == 'com.apple.iokit.IOCryptoAcceleratorFamily']
text = next(s for s in module if s['segment'] == '__TEXT_EXEC')
const = next(s for s in module if s['segment'] == '__DATA_CONST')


def read(va, size):
    at = np.backed_offset(native['segments'], va, size, len(candidate))
    return candidate[at:at + size]


def returned_address(va):
    a, add, ret = struct.unpack('<3I', read(va, 12))
    if a & 0x9f00001f != 0x90000000 or add & 0xffc003ff != 0x91000000 or ret != 0xd65f03c0:
        return None
    immediate = ((a >> 5 & 0x7ffff) << 2) | (a >> 29 & 3)
    if immediate & 0x100000:
        immediate -= 0x200000
    return (va & ~4095) + immediate * 4096 + (add >> 10 & 4095)


algorithm_slot = next(i for i, r in enumerate(slots) if '__ZN16IOAESAccelerator16getAlgorithmNameEv' in r['names'])
data = read(const['va'], const['size'])
matches = []
for offset in range(0, len(data) - (len(slots) + 2) * 8 + 1, 8):
    if data[offset:offset + 16] != bytes(16):
        continue
    pointer = struct.unpack_from('<Q', data, offset + 16 + algorithm_slot * 8)[0]
    if not text['va'] <= pointer < text['va'] + text['size'] - 12:
        continue
    name = returned_address(pointer)
    if name is not None and read(name, 8) == b'AES-CBC\0':
        matches.append(const['va'] + offset)
require(len(matches) == 1, 'Original AES table is not uniquely identified')
table = matches[0]
rows, inherited = [], 0
for index, row in enumerate(slots):
    pointer = struct.unpack('<Q', read(table + 16 + index * 8, 8))[0]
    actual = exports.get(pointer, [])
    if row['bind']:
        require(set(actual) & set(row['names']), f'Inherited method mismatch at slot {index}')
        inherited += 1
    else:
        require(text['va'] <= pointer < text['va'] + text['size'], f'Original method outside module at slot {index}')
    rows.append(dict(slot=index, reference_slot=row['reference_slot'], reference_names=row['names'],
                     candidate_target=hex(pointer), kernel_names=actual))
require(inherited == 162, 'Unexpected inherited method count')
meta = returned_address(int(rows[7]['candidate_target'], 16))
require(meta is not None, 'Unqualified original metaclass getter')
service_meta = next(va for va, names in exports.items() if '__ZN9IOService10gMetaClassE' in names)
obj = ROOT / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/libkern/DEVELOPMENT/OSMetaClass.cpo'
dwarf = subprocess.check_output(['xcrun', 'dwarfdump', '--name=OSMetaClass', '--show-children', obj], text=True)
layout = {}
for member in dwarf.split('DW_TAG_member')[1:]:
    name = re.search(r'DW_AT_name\s+\("([^"]+)"\)', member)
    position = re.search(r'DW_AT_data_member_location\s+\((0x[0-9a-f]+)\)', member)
    if name and position and name[1] in ('superClassLink', 'className', 'classSize'):
        layout[name[1]] = int(position[1], 16)
require(layout == dict(superClassLink=16, className=24, classSize=32), 'Compiled metaclass ABI changed')
snapshot = json.loads(args.snapshot.read_text())
require(snapshot['kernel_sha256'] == candidate_sha and not snapshot['bounded_timeout_interrupted'], 'Wrong or incomplete live metadata observation')
native_symbols = subprocess.check_output(['xcrun', 'nm', '-U', args.candidate], text=True)
bsd_init = re.search(r'^([0-9a-fA-F]+)\s+\S\s+_bsd_init$', native_symbols, re.M)
require(bsd_init and int(snapshot['pc'], 16) == int(bsd_init[1], 16), 'Snapshot did not reach actual bsd_init')


def observed(address):
    for key, value in snapshot['memory'].items():
        start, size = (int(x, 16) for x in key.split(':'))
        if start == address and size >= 40:
            return bytes.fromhex(value)
    for value in snapshot['indirect_memory'].values():
        if int(value['address'], 16) == address:
            return bytes.fromhex(value['bytes'])
    raise SystemExit(f'Missing actual guest metadata at {address:#x}')


aes_data, service_data = observed(meta), observed(service_meta)
crypto_meta = struct.unpack_from('<Q', aes_data, layout['superClassLink'])[0]
crypto_data = observed(crypto_meta)
require(struct.unpack_from('<Q', crypto_data, layout['superClassLink'])[0] == service_meta, 'Original parent does not bind actual source IOService')
sizes = [struct.unpack_from('<I', d, layout['classSize'])[0] for d in (aes_data, crypto_data, service_data)]
require(sizes == [0x120, 0x88, 0x88], 'Unexpected observed instance sizes')
registers = snapshot['system_registers']
tcr = int(registers['TCR_EL1'], 16)
require((tcr >> 14 & 3, tcr >> 30 & 3) == (0, 2), 'Live translation is not native 4K on both halves')
require(int(registers['SCTLR_EL1'], 16) & 1 and all(int(registers[r], 16) for r in ('TTBR0_EL1', 'TTBR1_EL1')), 'Inactive translation roots')
result = dict(reference_annotation_sha256=ref_sha, reference_executed_or_linked=False,
              candidate_sha256=candidate_sha, original_sha256=plan['original_sha256'],
              macos_padding_slots=104, ordinary_ios_method_slots=181, inherited_kernel_matches=inherited,
              vtable=hex(table), algorithm='AES-CBC', algorithm_slot=algorithm_slot, methods=rows,
              compiled_metaclass_offsets=layout, live_metaclasses=dict(IOAESAccelerator=hex(meta),
              IOCryptoAccelerator=hex(crypto_meta), IOService=hex(service_meta)),
              live_instance_sizes=dict(zip(('IOAESAccelerator', 'IOCryptoAccelerator', 'IOService'), sizes)),
              live_native_4k=True, live_registers=registers, request_structure_qualified=False,
              aes_operations_tested=False, service_registered=False, hardware_observation=False)
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(result, indent=2) + '\n')
print('PASS: 181 ordinary iOS slots, 162 inherited matches; live AES/parent/service sizes 0x120/0x88/0x88')
print('Reference-only ARM64e annotations and native 4K metadata; this class audit does not qualify private requests or provider operations.')
