#!/usr/bin/env python3
"""Qualify the unchanged target's mobile framebuffer dispatch contract on host."""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import backed_offset, exports, macho


def require(value, message):
    if not value:
        raise SystemExit(message)


candidate = ROOT / 'build/xnu-prelink/native-owner-mobile-graphics-candidate.macho'
image = candidate.read_bytes()
plan = json.loads(candidate.with_suffix('.json').read_text())
original = (ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed').read_bytes()
require(hashlib.sha256(image).hexdigest() == plan['candidate_sha256'] ==
        'aded28d3c61dafaf7b8a7c96b14427a798e9e95470ae6f287bcd038c07626798' and
        hashlib.sha256(original).hexdigest() == plan['original_sha256'] ==
        'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7', 'Require exact original and qualified candidate')
segments, original_segments = macho(image)['segments'], macho(original)['segments']
symbols = exports(image, macho(image))
by_name = {name: va for va, names in symbols.items() for name in names}
extents = [e for e in plan['extents'] if e['module'] == 'com.apple.iokit.IOMobileGraphicsFamily']
text = next(e for e in extents if e['segment'] == '__TEXT_EXEC')


def read(va, size):
    at = backed_offset(segments, va, size, len(image))
    return image[at:at + size]


def word(va):
    return struct.unpack('<I', read(va, 4))[0]


def address_pair(pc, register):
    first, second = struct.unpack('<2I', read(pc, 8))
    require(first & 0x9f00001f == (0x90000000 | register) and
            second & 0xffc003ff == (0x91000000 | register << 5 | register), 'Require original ADRP/ADD register pair')
    imm = ((first >> 5) & 0x7ffff) << 2 | ((first >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~4095) + (imm << 12) + ((second >> 10) & 4095)


require(hashlib.sha256(read(text['va'], text['size'])).hexdigest() ==
        plan['original_executable_sha256']['com.apple.iokit.IOMobileGraphicsFamily'], 'Original executable bytes changed')
obj = ROOT / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOUserClient.cpo'
layouts = {}
for name, size, members in (
        ('IOExternalMethodDispatch', 24, dict(function=0, checkScalarInputCount=8,
         checkStructureInputSize=12, checkScalarOutputCount=16, checkStructureOutputSize=20)),
        ('IOExternalMethodArguments', 248, dict(scalarInput=32, scalarInputCount=40,
         structureInput=48, structureInputSize=56, scalarOutput=72,
         scalarOutputCount=80, structureOutput=88, structureOutputSize=96))):
    dwarf = subprocess.check_output(['xcrun', 'dwarfdump', '--name=' + name, '--show-children', obj], text=True)
    found = re.search(r'DW_AT_name\s+\("' + name + r'"\)[\s\S]{0,150}?DW_AT_byte_size\s+\((0x[0-9a-f]+)\)', dwarf)
    require(found and int(found[1], 16) == size, 'Actual compiler structure size differs')
    for member, offset in members.items():
        found = re.search(r'DW_AT_name\s+\("' + member + r'"\)[\s\S]*?DW_AT_data_member_location\s+\((0x[0-9a-f]+)\)', dwarf)
        require(found and int(found[1], 16) == offset, 'Actual compiler field differs: ' + member)
    layouts[name] = dict(bytes=size, fields=members)

# The concrete factory's original constructor supplies this object's vptr.
vptr = address_pair(0xfffffff005776358, 8) + 16
require(word(0xfffffff005776360) == 0x91004108 and vptr == 0xfffffff005f34dd0,
        'Original userclient constructor vptr differs')
compiled = obj.read_bytes()
compiled_image = macho(compiled)
sym_at = next(at for cmd, at, _ in compiled_image['commands'] if cmd == 2)
symoff, count, stroff, _ = struct.unpack_from('<4I', compiled, sym_at + 8)
compiled_symbols = []
for i in range(count):
    name, _, _, _, value = struct.unpack_from('<IBBHQ', compiled, symoff + i * 16)
    compiled_symbols.append((compiled[stroff + name:compiled.index(b'\0', stroff + name)].decode(), value))
compiled_base = next(va for name, va in compiled_symbols if name == '__ZTV12IOUserClient')
relocations = {}
for segment in compiled_image['segments']:
    for section in segment['sections']:
        if section['va'] <= compiled_base < section['va'] + section['size']:
            at, count = struct.unpack_from('<II', compiled, section['command_offset'] + 56)
            for i in range(count):
                offset, bits = struct.unpack_from('<II', compiled, at + i * 8)
                if bits >> 27 & 1 and bits >> 28 == 0 and bits >> 25 & 3 == 3:
                    relocations[section['va'] + offset] = compiled_symbols[bits & 0xffffff][0]
slots = 0
while compiled_base + 16 + slots * 8 in relocations:
    slots += 1
base = by_name['__ZTV12IOUserClient']
require(slots == 186 and read(vptr - 16, 16) == bytes(16), 'Compiler-qualified native iOS IOUserClient table shape differs')
overrides = []
for slot in range(slots):
    parent, = struct.unpack('<Q', read(base + 16 + slot * 8, 8))
    require(parent == by_name[relocations[compiled_base + 16 + slot * 8]], 'Compiled native vtable slot identity differs')
    method, = struct.unpack('<Q', read(vptr + slot * 8, 8))
    if parent != method:
        require(text['va'] <= method < text['va'] + text['size'], 'Override must belong to original family code')
        overrides.append(dict(slot=slot, method=hex(method), native_parent_symbols=symbols.get(parent, [])))
require([e['slot'] for e in overrides] == [0, 1, 7, 14, 86, 87, 168, 172, 175, 178], 'Original override set differs')
external = int(next(e['method'] for e in overrides if e['slot'] == 168), 16)
require(external == 0xfffffff005778d40 and
        word(external + 0x54) == 0x71016908 and word(external + 0x58) == 0x1a9f27e8 and
        word(external + 0x5c) == 0x370000a8 and word(external + 0x64) == 0x32030fe8,
        'Original unsigned selector <90 check and kIOReturnInvalid refusal differ')
require(read(external + 0x7c, 16) == bytes.fromhex('006d40f9080040f908d942f900013fd6'),
        'All in-range requests must first call the actual provider at field 0xd8, virtual slot 182')
framebuffer_vptr = address_pair(0xfffffff00577b324, 8) + 16
require(word(0xfffffff00577b32c) == 0x91004108 and framebuffer_vptr == 0xfffffff005f35da0 and
        struct.unpack('<Q', read(framebuffer_vptr + 182 * 8, 8))[0] == by_name['___cxa_pure_virtual'],
        'Original base framebuffer constructor supplies a pure virtual provider pre-dispatch gate')
dispatch = address_pair(external + 0xf8, 9)
require(dispatch == address_pair(external + 0x164, 9) == address_pair(external + 0x1dc, 9) ==
        0xfffffff005f354c0, 'Three original paths must use the same 24-byte selector table')
rows = []
for selector in range(90):
    at = dispatch + selector * 24
    function, scalar_in, struct_in, scalar_out, struct_out = struct.unpack('<Q4I', read(at, 24))
    original_at = backed_offset(original_segments, at - plan['slide'], 24, len(original))
    source = struct.unpack_from('<Q4I', original, original_at)
    require(source[1:] == (scalar_in, struct_in, scalar_out, struct_out) and
            function == (source[0] + plan['slide'] if source[0] else 0), 'Exact original dispatch entry differs')
    require(not function or text['va'] <= function < text['va'] + text['size'], 'Dispatch action outside original executable')
    rows.append(dict(selector=selector, action=hex(function), scalar_input_count=scalar_in,
                     structure_input_bytes=struct_in, scalar_output_count=scalar_out, structure_output_bytes=struct_out))
jump_table = address_pair(external + 0xcc, 10)
require(jump_table == 0xfffffff005778f4c and word(external + 0xd4) == 0x10000008,
        'Original signed-offset jump table differs')
paths = {i + 68: external + 0xd4 + offset for i, offset in enumerate(struct.unpack('<18i', read(jump_table, 72)))}
input_dynamic = [i for i, va in paths.items() if va == external + 0xe4]
output_dynamic = [i for i, va in paths.items() if va == external + 0x150]
require(input_dynamic == [68, 78, 85] and output_dynamic == [79] and
        set(paths.values()) == {external + 0xe4, external + 0x150, external + 0x1bc}, 'Original dynamic dispatch paths differ')
require(word(external + 0x11c) == 0xb9403929 and word(external + 0x128) == 0xb9402929 and
        word(external + 0x188) == 0xb9406129 and word(external + 0x194) == 0xb9402929,
        'Dynamic checks must copy actual input/output byte size and scalar input count from compiler-qualified fields')
reserved = [e['selector'] for e in rows if e['action'] == '0xfffffff00577af74']
null = [e['selector'] for e in rows if e['action'] == '0x0']
require(null == [59, 60, 61, 62, 63, 64, 65, 70, 71] and len(reserved) == 14 and
        read(0xfffffff00577af98, 8) == bytes.fromhex('e05880520000bc72'), 'Reserved/null actions differ')
extension, = struct.unpack('<Q', read(vptr + 186 * 8, 8))
require(extension == 0xfffffff005776810, 'Original additional virtual entry differs')
result = dict(candidate_sha256=plan['candidate_sha256'], original_sha256=plan['original_sha256'],
              compiler_object_sha256=hashlib.sha256(obj.read_bytes()).hexdigest(), compiler_layouts=layouts,
              userclient_vptr=hex(vptr), native_virtual_slots=slots, overrides=overrides,
              original_additional_virtual_entry=dict(slot=186, method=hex(extension), name_qualified=False),
              external_method=hex(external), dispatch_table=hex(dispatch), methods=rows,
              null_actions=null, reserved_unsupported_actions=reserved,
              dynamic_input_size_selectors=input_dynamic, dynamic_output_size_selectors=output_dynamic,
              provider_field=0xd8, provider_pre_dispatch_slot=182,
              base_framebuffer_vptr=hex(framebuffer_vptr), base_provider_gate_pure_virtual=True, static_only=True,
              runtime_client_created=False, backend_contract_complete=False)
output = ROOT / 'build/display-analysis/mobile-graphics-userclient-abi.json'
output.write_text(json.dumps(result, indent=2) + '\n')
print('PASS: compiler-qualified 186-slot native base, 90 unchanged selector rows, nine null and 14 reserved actions')
print('PASS: original range refusal, provider pre-dispatch gate, and four dynamic-size selector paths; static evidence only')
