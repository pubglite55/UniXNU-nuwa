#!/usr/bin/env python3
"""Qualify actual IR3 constant/I/O ABI and native bounded constant packing."""
import argparse
import ctypes as C
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import struct
import subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--compiler',type=Path,required=True)
a=p.parse_args()
ROOT=Path(__file__).resolve().parents[1]
KIT=ROOT/'kits/AirNir'
OUT=ROOT/'build/air-nir/constant-uploads'
OUT.mkdir(parents=True,exist_ok=True)
env={k:v for k,v in os.environ.items() if not k.startswith(('IR3_','FD_MESA_','NIR_','MESA_SHADER_'))}
env['IR3_SHADER_DEBUG']='asmroundtrip'


def run(command,timeout=30):
    r=subprocess.run([str(x) for x in command],env=env,capture_output=True,text=True,timeout=timeout)
    if r.returncode:raise RuntimeError(f'Status {r.returncode}: {r.stderr[-2000:]}')
    return r.stdout.strip()


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


# Sanitized synthetic controls include actual unreadable pages after 8/80 bytes.
test=OUT/'guarded-test'
run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=address,undefined',
     KIT/'ConstantUploads.c',KIT/'tests/test_constant_uploads.c','-o',test])
unit=run([test])
if not unit.startswith('PASS: 33 guarded constant upload cases;'):raise RuntimeError('Guard test inventory differs')
shared=OUT/'ConstantUploads.dylib'
run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-O2','-dynamiclib',KIT/'ConstantUploads.c','-o',shared])
# Native ordinary ARM64/iOS 17 cross-build, no LLVM/NIR or host-only imports.
obj=OUT/'ConstantUploads.ios.o'
clang=run(['xcrun','--sdk','iphoneos','--find','clang'])
run([clang,'-target','arm64-apple-ios17.0','-std=c11','-O2','-Wall','-Wextra','-Werror',
     '-ffreestanding','-fstack-protector-strong','-c',KIT/'ConstantUploads.c','-o',obj])
data=obj.read_bytes()
magic,cpu,subtype,kind,ncmds,cmdbytes,flags,reserved=struct.unpack_from('<8I',data)
if (magic,cpu,subtype,kind)!=(0xfeedfacf,0x100000c,0,1):raise RuntimeError('Native target Mach-O header differs')
platforms=[];offset=32
for _ in range(ncmds):
    cmd,size=struct.unpack_from('<II',data,offset)
    if size<8 or offset+size>len(data):raise RuntimeError('Invalid target object load command')
    if cmd==0x32:platforms.append(struct.unpack_from('<II',data,offset+8))
    offset+=size
if platforms!=[(2,17<<16)]:raise RuntimeError('Native target deployment/platform differs')
imports=run(['nm','-u',obj]).splitlines()
allowed={'___stack_chk_fail','___stack_chk_guard','_memcpy','_memset'}
if any(line.split()[-1] not in allowed for line in imports):raise RuntimeError('Native object has unexpected imports')

cpp_obj=OUT/'ConstantUploads.cpp-client.ios.o'
run([clang,'-x','c++','-std=c++17','-target','arm64-apple-ios17.0','-O2','-Wall','-Wextra','-Werror',
     '-ffreestanding','-fno-exceptions','-fno-rtti','-fstack-protector-strong','-c',
     KIT/'tests/constant_cpp_client.cpp','-o',cpp_obj])
cpp_header=struct.unpack_from('<8I',cpp_obj.read_bytes())
if cpp_header[:4]!=(0xfeedfacf,0x100000c,0,1):raise RuntimeError('C++ consumer target subtype differs')
cpp_imports=run(['nm','-u',cpp_obj]).splitlines()
if [line.split()[-1] for line in cpp_imports]!=['_air_pack_constants']:
    raise RuntimeError('Native C++ consumer did not use the exact native C symbol')
archive=OUT/'libAirConstantUploads.ios.a'
run(['xcrun','--sdk','iphoneos','ar','rcs',archive,obj])

class Read(C.Structure):_fields_=[('binding',C.c_uint32),('offset',C.c_uint32),('bytes',C.c_uint32)]
class Range(C.Structure):_fields_=[('binding',C.c_uint32),('source_begin',C.c_uint32),('source_end',C.c_uint32),('destination_begin',C.c_uint32)]
class Binding(C.Structure):_fields_=[('data',C.c_void_p),('bytes',C.c_size_t),('minimum_bytes',C.c_size_t)]
class Layout(C.Structure):_fields_=[('constant_bytes',C.c_uint32),('upload_alignment',C.c_uint32),('ubo_begin',C.c_uint32),('ubo_bytes',C.c_uint32),('ranges',C.POINTER(Range)),('range_count',C.c_size_t),('reads',C.POINTER(Read)),('read_count',C.c_size_t),('immediate_begin',C.c_uint32),('immediate_words',C.c_uint32),('immediates',C.POINTER(C.c_uint32))]
class Result(C.Structure):_fields_=[('status',C.c_uint32),('written_bytes',C.c_uint32),('padded_bytes',C.c_uint32)]
lib=C.CDLL(str(shared))
pack=lib.air_pack_constants;pack.argtypes=[C.POINTER(Layout),C.POINTER(Binding),C.c_void_p,C.c_size_t];pack.restype=Result
libc=C.CDLL(None);libc.mprotect.argtypes=[C.c_void_p,C.c_size_t,C.c_int];libc.mprotect.restype=C.c_int
page=mmap.PAGESIZE
prefixes=[ROOT/f'build/air-nir/QuartzCore-111']+[ROOT/f'build/air-nir/RenderBox-{i}' for i in (0,2,26,28,45,65,71)]
prefixes += [ROOT/f'build/air-nir/resources/QuartzCore-{i}' for i in (7,8,9,10,11,98)]
reports=[]
for prefix in prefixes:
    # Refresh ABI with current compiler; original code/source identity is checked
    # against the completed input inventory by the outer build harness.
    library='RenderBox' if prefix.name.startswith('RenderBox') else 'QuartzCore'
    index=int(prefix.name.split('-')[-1])
    src=ROOT/f'build/gpu-analysis/air/{library}/module-{index}.bc'
    source_audit=json.loads((ROOT/'build/gpu-analysis/air/target-inputs.json').read_text())
    original=next(m for m in source_audit['modules'] if m['library']==library and m['index']==index)
    if sha(src)!=original['bitcode_sha256']:raise RuntimeError('Original input hash differs')
    run([a.compiler,src,'0x43050a01',prefix,'--compile'])
    abi=json.loads(prefix.with_suffix('.ir3.json').read_text())
    source=json.loads(prefix.with_suffix('.interface.json').read_text())
    assembly=prefix.with_suffix('.asm').read_text()
    binary=prefix.with_suffix('.bin').read_bytes()
    if (abi['format_version']!=1 or abi['stage']!='vertex' or abi['generation']!=7 or
        abi['gpu_name']!='FD740' or abi['chip_id']!='0x43050a01' or abi['gpu_executed'] or abi['runtime_binding_qualified'] or
        abi['binary_bytes']!=len(binary) or abi['code_dwords']*4>len(binary) or
        abi['binary_alignment_bytes']!=128 or len(binary)%128 or abi['upload_alignment_bytes']!=64 or
        abi['constant_data_bytes'] or abi['private_bytes_per_fiber'] or
        abi['remaining_ubo_slots'] or abi['push_ubo_with_preamble'] or abi['load_shader_consts_via_preamble']):
        raise RuntimeError('Target ABI capability/configuration differs; do not assume newer A7xx behavior')
    if abi['driver_parameter_words'] or any(abi[k]>=0 for k in ('driver_params_ubo','primitive_params_ubo','primitive_map_ubo')):
        raise RuntimeError('New driver-owned UBO/parameter requirement needs independent qualification')
    allocations={v['name']:v for v in abi['allocations']}
    printed={name:(int(begin)*16,int(words)*16) for name,begin,words in re.findall(r'^;   (\w+)\s+c(\d+)\.x \((\d+) vec4\)$',assembly,re.M)}
    printed={('primitive_params' if name=='primitive_param' else name):value for name,value in printed.items()}
    if printed!={v['name']:(v['begin'],v['bytes']) for v in abi['allocations'] if v['bytes']}:
        raise RuntimeError('Actual struct allocation units differ from independent disassembly')
    imm=abi['immediates']
    shown=[]
    for reg,values in re.findall(r'^@const\(c(\d+)\.x\)\s+(.+)$',assembly,re.M):
        if int(reg)*16 != imm['destination_begin']+len(shown)*4:raise RuntimeError('Immediate destination differs')
        shown += [int(value,16) for value in re.findall(r'0x[0-9a-f]+',values)]
    if shown!=imm['values'] or len(shown)!=imm['padded_words'] or imm['logical_words']>len(shown) or not imm['cpu_upload']:
        raise RuntimeError('Omitted/corrupt immediate pool')
    ranges=(Range*len(abi['ubo_ranges']))(*(Range(r['binding'],r['source_begin'],r['source_end'],r['destination_begin']) for r in abi['ubo_ranges']))
    reads=(Read*len(abi['source_reads']))(*(Read(r['binding'],r['offset'],r['bytes']) for r in abi['source_reads']))
    for r in abi['ubo_ranges']:
        if r['bindless'] or r['global']:raise RuntimeError('Unsupported resource promotion kind')
    immediates=(C.c_uint32*len(shown))(*shown)
    alloc=allocations['ubo_ranges']
    layout=Layout(abi['constant_bytes'],abi['upload_alignment_bytes'],alloc['begin'],alloc['bytes'],ranges,len(ranges),reads,len(reads),imm['destination_begin'],len(shown),immediates)
    bindings=(Binding*16)();backings=[];original_bytes={}
    for item in source['inputs']:
        if item['kind']!='air.buffer':continue
        size=item['minimum_bytes'];slot=item['index']
        if size>page:raise RuntimeError('Guarded fixture currently supports one page per actual source binding')
        memory=mmap.mmap(-1,page*2,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,prot=mmap.PROT_READ|mmap.PROT_WRITE)
        base=C.addressof(C.c_char.from_buffer(memory));address=base+page-size
        if address%item['minimum_alignment']:raise RuntimeError('Original source alignment not met')
        contents=bytes((slot*29+i*7)&255 for i in range(size))
        C.memmove(address,contents,size)
        if libc.mprotect(base+page,page,0):raise RuntimeError('Guard page protection failed')
        bindings[slot]=Binding(address,size,size);original_bytes[slot]=contents;backings.append(memory)
    image=(C.c_uint8*abi['constant_bytes'])(*([0x6b]*abi['constant_bytes']))
    result=pack(C.byref(layout),bindings,image,len(image))
    if result.status:raise RuntimeError(f'Actual compiler layout refused: {prefix.name}, status {result.status}')
    expected=bytearray([0x6b]*len(image));written=set();padded=0
    for r in abi['ubo_ranges']:
        data=original_bytes[r['binding']]
        for offset in range(r['source_begin'],r['source_end']):
            dest=r['destination_begin']+offset-r['source_begin']
            expected[dest]=data[offset] if offset<len(data) else 0
            padded+=int(offset>=len(data));written.add(dest)
    for i,value in enumerate(shown):
        dest=imm['destination_begin']+i*4;expected[dest:dest+4]=struct.pack('<I',value);written.update(range(dest,dest+4))
    if bytes(image)!=expected or result.written_bytes!=len(written) or result.padded_bytes!=padded:
        raise RuntimeError('Actual constant image, untouched allocations or padding differs')
    for read in abi['source_reads']:
        r=next(r for r in abi['ubo_ranges'] if r['binding']==read['binding'] and r['source_begin']<=read['offset'] and read['offset']+read['bytes']<=r['source_end'])
        dest=r['destination_begin']+read['offset']-r['source_begin']
        if bytes(image)[dest:dest+read['bytes']]!=original_bytes[read['binding']][read['offset']:read['offset']+read['bytes']]:
            raise RuntimeError('A shader read would consume padding or the wrong buffer')
    reports.append(dict(library=library,index=index,binary_sha256=sha(prefix.with_suffix('.bin')),
        abi_sha256=sha(prefix.with_suffix('.ir3.json')),constant_bytes=len(image),ranges=len(ranges),
        immediate_words=len(shown),source_reads=len(reads),written_bytes=result.written_bytes,padded_bytes=padded,
        protected_short_bindings=True,internal_allocations_untouched=True,gpu_executed=False))
    for memory in backings:memory.close()
(OUT/'report.json').write_text(json.dumps(dict(original_layouts=reports,guarded_unit_result=unit,
    native_object_sha256=sha(obj),native_platform=2,native_minimum_os='17.0',native_arm64_subtype=0,
    native_imports=imports,native_cpp_client_sha256=sha(cpp_obj),native_cpp_imports=cpp_imports,
    native_archive_sha256=sha(archive),host_library_sha256=sha(shared),runtime_binding_qualified=False,
    generated_isa_executed=False),indent=2)+'\n')
print('PASS: 14 actual IR3 layouts packed, immediate pools preserved, protected short bindings and internal allocation sentinels intact')
print('PASS: 33 ASan/UBSan guard/refusal cases and ordinary ARM64/iOS17 cross-build')
