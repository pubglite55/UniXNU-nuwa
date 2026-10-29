#!/usr/bin/env python3
"""Check actual AIR/IR3 parameter images through native A740 direct PM4 encoding."""
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import macho
OUT = ROOT / 'build/adreno-constant-commands'
OUT.mkdir(parents=True, exist_ok=True)
KIT = ROOT / 'kits/AdrenoPM4'
MESA = ROOT / '.cache/mesa-work'
REV = '85fda3b36405bcaea8bffc64aa4f2651dc90770d'


def run(cmd, **kw):
    return subprocess.check_output([str(v) for v in cmd], timeout=30, **kw)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


if run(['git', '-C', MESA, 'rev-parse', 'HEAD'], text=True).strip() != REV:
    raise SystemExit('Pinned Mesa revision differs')
paths = ['src/gallium/drivers/freedreno/a6xx/fd6_const.cc',
         'src/gallium/drivers/freedreno/a6xx/fd6_emit.h',
         'src/gallium/drivers/freedreno/ir3/ir3_const.h',
         'src/freedreno/registers/adreno/adreno_pm4.xml',
         'src/freedreno/common/freedreno_pm4.h']
documents = {p: run(['git', '-C', MESA, 'show', REV + ':' + p]) for p in paths}
manifest = json.loads((ROOT / 'scripts/data/adreno-constant-inputs.json').read_text())
if manifest['mesa_revision'] != REV or manifest['files'] != {p: sha(raw) for p, raw in documents.items()}:
    raise SystemExit('Exact reference source hashes differ')
for p in paths[3:]:
    if (MESA / p).read_bytes() != documents[p]:
        raise SystemExit('Actual encoder/XML reference working source differs')
xml = ET.fromstring(documents[paths[3]])
ns = {'r': xml.tag.split('}')[0].lstrip('{')}
domain = xml.find("r:domain[@name='CP_LOAD_STATE6']", ns)
fields = {v.attrib['name']: (int(v.attrib['low']), int(v.attrib['high']))
          for v in domain.find("r:reg32[@name='0']", ns)}
enums = {v.attrib['name']: int(v.attrib['value'], 0) for enum in xml.findall('.//r:enum', ns) for v in enum.findall('r:value', ns) if 'value' in v.attrib}
# Build the unit oracle against the actual Mesa-generated XML/header functions.
test = OUT / 'test-constants'
run(['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
     '-fsanitize=address,undefined', '-DMESA_REFERENCE',
     '-I', ROOT / 'build/mesa-ir3/src/freedreno/registers/adreno',
     '-I', MESA / 'src/freedreno/common', KIT / 'AdrenoPM4.c', KIT / 'AdrenoConstants.c',
     KIT / 'test_constants.c', '-o', test])
unit = run([test], text=True).strip()
if not unit.startswith('PASS: 9202 direct upload cases,'):
    raise SystemExit('Native unit inventory changed')
print(unit)
objects = []
native_imports = {}
for name in ('AdrenoPM4', 'AdrenoConstants'):
    obj = OUT / (name + '.ios.o')
    run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
         '-Wno-incompatible-sysroot', '-ffreestanding', '-fstack-protector-strong', '-c', KIT / (name + '.c'), '-o', obj])
    parsed = macho(obj.read_bytes())
    version = next(at for cmd, at, _ in parsed['commands'] if cmd == 0x32)
    if parsed['kind'] != 1 or struct.unpack_from('<II', obj.read_bytes(), version+8) != (2, 0x110000):
        raise SystemExit('Ordinary ARM64/iOS17 object required')
    imports = run(['xcrun', 'nm', '-u', obj], text=True).split()
    native_imports[name] = imports
    checked = [v for v in imports if v not in ('___stack_chk_fail', '___stack_chk_guard')]
    if checked != ([] if name == 'AdrenoPM4' else ['_AdrenoPM4Type7']):
        raise SystemExit('Unexpected runtime import: ' + repr(imports))
    objects.append(obj)
archive = OUT / 'libAdrenoConstants.ios.a'
archive.unlink(missing_ok=True)
run(['xcrun', 'ar', 'rcs', archive, *objects], env=dict(os.environ, ZERO_AR_DATE='1'))
cpp = OUT / 'client.cpp'
cpp.write_text('#include "AdrenoConstants.h"\nextern "C" AdrenoConstantResult client(const AdrenoConstantConfig *c,const AdrenoConstantSpan *s,const unsigned char *b,unsigned *o) {return AdrenoA740Constants(c,s,1,b,16,o,8);}\n')
cpp_obj = OUT / 'client.ios.o'
run(['xcrun', 'clang++', '-target', 'arm64-apple-ios17.0', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
     '-Wno-incompatible-sysroot', '-ffreestanding', '-fno-exceptions', '-fno-rtti', '-I', KIT, '-c', cpp, '-o', cpp_obj])
if run(['xcrun', 'nm', '-u', cpp_obj], text=True).split() != ['_AdrenoA740Constants']:
    raise SystemExit('Native C++ linkage differs')
shared = OUT / 'Constants.dylib'
run(['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-dynamiclib',
     KIT / 'AdrenoPM4.c', KIT / 'AdrenoConstants.c', ROOT / 'kits/AirNir/ConstantUploads.c', '-o', shared])

class Read(C.Structure): _fields_ = [('binding', C.c_uint32), ('offset', C.c_uint32), ('bytes', C.c_uint32)]
class Range(C.Structure): _fields_ = [('binding', C.c_uint32), ('source_begin', C.c_uint32), ('source_end', C.c_uint32), ('destination_begin', C.c_uint32)]
class Binding(C.Structure): _fields_ = [('data', C.c_void_p), ('bytes', C.c_size_t), ('minimum_bytes', C.c_size_t)]
class Layout(C.Structure):
    _fields_ = [('constant_bytes', C.c_uint32), ('upload_alignment', C.c_uint32), ('ubo_begin', C.c_uint32), ('ubo_bytes', C.c_uint32),
                ('ranges', C.POINTER(Range)), ('range_count', C.c_size_t), ('reads', C.POINTER(Read)), ('read_count', C.c_size_t),
                ('immediate_begin', C.c_uint32), ('immediate_words', C.c_uint32), ('immediates', C.POINTER(C.c_uint32))]
class Result(C.Structure): _fields_ = [('status', C.c_uint32), ('a', C.c_uint32), ('b', C.c_uint32)]
class Config(C.Structure): _fields_ = [('chip', C.c_uint64), ('stage', C.c_uint32), ('bytes', C.c_uint32)]
class Span(C.Structure): _fields_ = [('source', C.c_uint32), ('destination', C.c_uint32), ('bytes', C.c_uint32)]
lib = C.CDLL(str(shared))
pack = lib.air_pack_constants
pack.argtypes = [C.POINTER(Layout), C.POINTER(Binding), C.c_void_p, C.c_size_t]; pack.restype = Result
emit = lib.AdrenoA740Constants
emit.argtypes = [C.POINTER(Config), C.POINTER(Span), C.c_size_t, C.c_void_p, C.c_size_t, C.POINTER(C.c_uint32), C.c_size_t]; emit.restype = Result
previous = json.loads((ROOT / 'build/air-nir/constant-uploads/report.json').read_text())['original_layouts']
results = []
for old in previous:
    library, index = old['library'], old['index']
    prefix = ROOT / ('build/air-nir/resources' if library == 'QuartzCore' and index != 111 else 'build/air-nir') / f'{library}-{index}'
    if sha(prefix.with_suffix('.ir3.json').read_bytes()) != old['abi_sha256'] or sha(prefix.with_suffix('.bin').read_bytes()) != old['binary_sha256']:
        raise SystemExit('Actual compiler/layout identity differs')
    abi = json.loads(prefix.with_suffix('.ir3.json').read_text())
    interface = json.loads(prefix.with_suffix('.interface.json').read_text())
    if abi['chip_id'] != '0x43050a01' or abi['stage'] != 'vertex' or abi['load_shader_consts_via_preamble']:
        raise SystemExit('Unsupported actual variant')
    reads = (Read * len(abi['source_reads']))(*(Read(r['binding'], r['offset'], r['bytes']) for r in abi['source_reads']))
    ranges = (Range * len(abi['ubo_ranges']))(*(Range(r['binding'], r['source_begin'], r['source_end'], r['destination_begin']) for r in abi['ubo_ranges']))
    bindings = (Binding * 16)(); backing = []
    for item in interface['inputs']:
        if item['kind'] == 'air.buffer':
            size, slot = item['minimum_bytes'], item['index']
            data = (C.c_uint8 * size)(*(i*7+slot*29 & 255 for i in range(size)))
            backing.append(data); bindings[slot] = Binding(C.addressof(data), size, size)
    imm = abi['immediates']; values = (C.c_uint32 * len(imm['values']))(*imm['values'])
    ubo = next(v for v in abi['allocations'] if v['name'] == 'ubo_ranges')
    layout = Layout(abi['constant_bytes'], abi['upload_alignment_bytes'], ubo['begin'], ubo['bytes'], ranges, len(ranges), reads, len(reads), imm['destination_begin'], len(values), values)
    image = (C.c_uint8 * abi['constant_bytes'])(*([0x6b] * abi['constant_bytes']))
    packed = pack(C.byref(layout), bindings, image, len(image))
    if packed.status or packed.a != old['written_bytes'] or packed.b != old['padded_bytes']:
        raise SystemExit('Actual prepared parameters differ')
    intervals = [(r['destination_begin'], r['source_end'] - r['source_begin']) for r in abi['ubo_ranges']]
    if imm['padded_words']: intervals.append((imm['destination_begin'], imm['padded_words']*4))
    spans = (Span * len(intervals))(*(Span(offset, offset, size) for offset, size in intervals))
    cfg = Config(0x43050a01, 0, len(image)); output = (C.c_uint32 * 2304)(*([0x6b6b6b6b] * 2304))
    r = emit(C.byref(cfg), spans, len(spans), image, len(image), output, len(output))
    if r.status or r.b != len(intervals): raise SystemExit('Actual parameter intervals refused')
    fallback = (C.c_uint32 * 2304)(*([0x6b6b6b6b] * 2304))
    cfg.chip = 0xffff43050a01
    alternate = emit(C.byref(cfg), spans, len(spans), image, len(image), fallback, len(fallback))
    if alternate.status or alternate.a != r.a or alternate.b != r.b or bytes(fallback) != bytes(output):
        raise SystemExit('Observed complete chip identity changed actual command encoding')
    encoded = bytes(output)[:r.a*4]; restored = bytearray(b'\x6b' * len(image)); at = 0
    for offset, size in intervals:
        header, state, low, high = struct.unpack_from('<4I', encoded, at)
        opcode, payload = header >> 16 & 127, header & 0x3fff
        if header >> 28 != 7 or opcode != enums['CP_LOAD_STATE6_GEOM'] or payload != 3 + size//4 or low or high:
            raise SystemExit('Unexpected command/opcode/address')
        for field, expected in [('DST_OFF', offset//16), ('STATE_TYPE', enums['ST6_CONSTANTS']), ('STATE_SRC', enums['SS6_DIRECT']), ('STATE_BLOCK', enums['SB6_VS_SHADER']), ('NUM_UNIT', size//16)]:
            lo, hi = fields[field]
            if (state >> lo) & ((1 << (hi-lo+1))-1) != expected: raise SystemExit('XML field mismatch: '+field)
        restored[offset:offset+size] = encoded[at+16:at+16+size]; at += (1+payload)*4
    if restored != bytes(image) or at != len(encoded) or bytes(output)[at:] != b'\x6b'*(len(output)*4-at):
        raise SystemExit('Payload, undeclared allocation or output tail differs')
    (OUT / f'{library}-{index}.pm4').write_bytes(encoded)
    results.append(dict(library=library, index=index, abi_sha256=old['abi_sha256'], binary_sha256=old['binary_sha256'],
        command_sha256=sha(encoded), command_words=r.a, packets=r.b, transferred_bytes=packed.a,
        only_explicit_intervals=True, indirect_gpu_addresses=False, full_chip_identity_profiles=2, gpu_execution=False))
report = dict(mesa_revision=REV, source_documents=manifest['files'], unit=unit, layouts=results,
    source_sha256={str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in (KIT/'AdrenoPM4.c', KIT/'AdrenoConstants.c', KIT/'AdrenoConstants.h', ROOT/'kits/AirNir/ConstantUploads.c')},
    native_imports=native_imports, native_objects={p.name: sha(p.read_bytes()) for p in objects}, native_archive_sha256=sha(archive.read_bytes()),
    native_cpp_sha256=sha(cpp_obj.read_bytes()), ordinary_arm64_ios17=True,
    actual_submission=False, gpu_execution=False, metal_device=False)
(OUT / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
print('PASS: 14 actual IR3 parameter images through PM4/XML decode, no unowned intervals uploaded; native ARM64/iOS17 C/C++ archive')
