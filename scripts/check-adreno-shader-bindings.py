#!/usr/bin/env python3
"""Qualify A740 shader-register encoding from actual IR3 metadata, without GPU access."""
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'kits/XnuPrelink'))
from native_prelink import macho
OUT=ROOT/'build/adreno-shader-bindings';OUT.mkdir(parents=True,exist_ok=True)
KIT=ROOT/'kits/AdrenoPM4';MESA=ROOT/'.cache/mesa-work';REV='85fda3b36405bcaea8bffc64aa4f2651dc90770d'
BASE=MESA/'src/freedreno/registers'
def run(cmd,**kw):return subprocess.check_output([str(v) for v in cmd],timeout=30,**kw)
def sha(raw):return hashlib.sha256(raw).hexdigest()
manifest=json.loads((ROOT/'scripts/data/adreno-shader-inputs.json').read_text())
if run(['git','-C',MESA,'rev-parse','HEAD'],text=True).strip()!=REV or manifest['mesa_revision']!=REV:raise SystemExit('Pinned Mesa identity differs')
for name,digest in manifest['files'].items():
    raw=run(['git','-C',MESA,'show',REV+':'+name])
    if sha(raw)!=digest:raise SystemExit('Reference source differs')
    p=MESA/name
    if p.exists() and p.read_bytes()!=raw:raise SystemExit('Working reference differs: '+name)
    if name.endswith('fd6_program.cc'):(OUT/'fd6_program.cc').write_bytes(raw)
for name in ('adreno_common','adreno_pm4','a6xx_enums','a7xx_enums','a8xx_enums','a6xx'):
    raw=run([ROOT/'.cache/mesa-venv/bin/python',BASE/'gen_header.py','--rnn',BASE,'--xml',BASE/'adreno'/(name+'.xml'),'c-defines'])
    (OUT/(name+'.xml.h')).write_bytes(raw)
# C unit uses actual generated register/header functions as an independent oracle.
includes=['-I',OUT,'-I',MESA/'src/freedreno/common','-I',ROOT/'build/mesa-ir3','-I',MESA/'src','-I',MESA/'include']
unit=OUT/'test-shader'
run(['xcrun','clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-DMESA_REFERENCE','-DFD_NO_DEPRECATED_PACK',
     *includes,KIT/'AdrenoPM4.c',KIT/'AdrenoShader.c',KIT/'test_shader.c','-o',unit])
unit_result=run([unit],text=True).strip()
if not unit_result.startswith('PASS: 16644 shader register cases,'):raise SystemExit('Shader unit inventory changed')
print(unit_result)
objects=[];imports={}
for name in ('AdrenoPM4','AdrenoConstants','AdrenoShader'):
    obj=OUT/(name+'.ios.o')
    run(['xcrun','clang','-target','arm64-apple-ios17.0','-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-incompatible-sysroot',
         '-ffreestanding','-fstack-protector-strong','-c',KIT/(name+'.c'),'-o',obj])
    parsed=macho(obj.read_bytes());version=next(at for cmd,at,_ in parsed['commands'] if cmd==0x32)
    if parsed['kind']!=1 or struct.unpack_from('<II',obj.read_bytes(),version+8)!=(2,0x110000):raise SystemExit('Require ordinary ARM64/iOS17 object')
    symbols=run(['xcrun','nm','-u',obj],text=True).split();imports[name]=symbols
    other=[v for v in symbols if v not in ('___stack_chk_fail','___stack_chk_guard')]
    if other!=({'AdrenoPM4':[], 'AdrenoConstants':['_AdrenoPM4Type7'], 'AdrenoShader':['_AdrenoPM4Type4']}[name]):raise SystemExit('Unexpected shader runtime imports')
    objects.append(obj)
archive=OUT/'libAdrenoCommands.ios.a';archive.unlink(missing_ok=True)
run(['xcrun','ar','rcs',archive,*objects],env=dict(os.environ,ZERO_AR_DATE='1'))
cpp=OUT/'client.cpp'
cpp.write_text('#include "AdrenoShader.h"\n#include <stddef.h>\n'
    'static_assert(sizeof(AdrenoConstantConfig)==16 && offsetof(AdrenoConstantConfig,stage)==8);\n'
    'static_assert(sizeof(AdrenoShaderState)==64 && sizeof(AdrenoShaderMapping)==40);\n'
    'extern "C" unsigned client(const AdrenoShaderState *s,const AdrenoShaderMapping *m,const AdrenoConstantConfig *c,const AdrenoConstantSpan *p,const unsigned char *b,unsigned *o){auto a=AdrenoA740ShaderBind(s,m,o,24);auto t=AdrenoA740Constants(c,p,1,b,16,o+24,8);return a.status|t.status;}\n')
cpp_obj=OUT/'client.ios.o'
run(['xcrun','clang++','-target','arm64-apple-ios17.0','-std=c++17','-O2','-Wall','-Wextra','-Werror','-Wno-incompatible-sysroot',
     '-ffreestanding','-fno-exceptions','-fno-rtti','-I',KIT,'-c',cpp,'-o',cpp_obj])
if run(['xcrun','nm','-u',cpp_obj],text=True).split()!=['_AdrenoA740Constants','_AdrenoA740ShaderBind']:raise SystemExit('Native shader C++ ABI differs')
# Link the C++ consumer and all command helpers into a real target-native
# dylib. One archive avoids duplicated PM4 objects under whole-archive loading.
sdk=run(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
native=OUT/'AdrenoCommands.ios.dylib'
run(['xcrun','clang','-target','arm64-apple-ios17.0','-isysroot',sdk,'-dynamiclib',cpp_obj,archive,
     '-Wl,-install_name,@rpath/AdrenoCommands.ios.dylib','-Wl,-undefined,error','-o',native])
parsed_native=macho(native.read_bytes())
version=next(at for cmd,at,_ in parsed_native['commands'] if cmd==0x32)
if parsed_native['kind']!=6 or struct.unpack_from('<II',native.read_bytes(),version+8)!=(2,0x110000):
    raise SystemExit('Real target-native linked module has wrong architecture/platform')
native_imports=run(['xcrun','nm','-u',native],text=True).split()
if not set(native_imports)<=set(['___stack_chk_fail','___stack_chk_guard','dyld_stub_binder']):
    raise SystemExit('Native linked module has unresolved helper or unexpected runtime dependency')
shared=OUT/'Shader.dylib'
run(['xcrun','clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-dynamiclib',KIT/'AdrenoPM4.c',KIT/'AdrenoShader.c','-o',shared])
class State(C.Structure):
    _fields_=[('chip',C.c_uint64),('stage',C.c_uint32),('binary',C.c_uint32),('groups',C.c_uint32),('full',C.c_int32),('half',C.c_int32)]+[(v,C.c_uint32) for v in ('stack','merged','early','double','inputs','quad','lod','private','constant')]
class Mapping(C.Structure):_fields_=[(v,C.c_uint64) for v in ('context','base','bytes','offset')]+[('shift',C.c_uint32),('readonly',C.c_uint32)]
class Result(C.Structure):_fields_=[('status',C.c_uint32),('words',C.c_uint32),('registers',C.c_uint32)]
lib=C.CDLL(str(shared));bind=lib.AdrenoA740ShaderBind
bind.argtypes=[C.POINTER(State),C.POINTER(Mapping),C.POINTER(C.c_uint32),C.c_size_t];bind.restype=Result
xml=ET.fromstring((BASE/'adreno/a6xx.xml').read_bytes());ns={'r':xml.tag.split('}')[0].lstrip('{')};domain=xml.find("r:domain[@name='A6XX']",ns)
regs={v.attrib['name']:v for v in domain if v.tag in (f"{{{ns['r']}}}reg32",f"{{{ns['r']}}}reg64")}
bitsets={v.attrib['name']:v for v in domain.findall('r:bitset',ns)}
enums={v.attrib['name']:int(v.attrib['value'],0) for enum in xml.findall('.//r:enum',ns) for v in enum.findall('r:value',ns) if 'value' in v.attrib}
def offset(name):return int(regs[name].attrib['offset'],0)
def field(register,name,value):
    reg=regs[register];nodes=list(reg)
    if reg.attrib.get('type') in bitsets:nodes+=list(bitsets[reg.attrib['type']])
    matches=[v for v in nodes if v.tag.endswith('bitfield') and v.attrib.get('name')==name]
    if len(matches)!=1:raise RuntimeError('Ambiguous reference field: '+name)
    v=matches[0];lo=int(v.attrib.get('low',v.attrib.get('pos')));hi=int(v.attrib.get('high',lo))
    if 'A8XX' in v.attrib.get('variants','') and register=='TPL1_MODE_CNTL':raise RuntimeError('A8-only field must not be emitted')
    if not 0<=value<(1<<(hi-lo+1)):raise RuntimeError('Reference value does not fit field')
    return value<<lo
report=json.loads((ROOT/'build/air-nir/report.json').read_text())
entries=[(v,ROOT/'build/air-nir') for v in report['original_cases']]
entries += [(v,ROOT/'build/air-nir/resources') for v in report['original_resource_checks']['originals']]
entries += [(v,ROOT/'build/air-nir/fragments') for v in report['original_fragment_checks']['originals']]
entries += [(v,ROOT/'build/air-nir/fragment-inputs') for v in report['original_fragment_input_checks']['originals']]
if len(entries)!=22:raise SystemExit('Exact original shader inventory required')
results=[]
for entry,base in entries:
    library,index=entry['library'],entry['index'];prefix=base/f'{library}-{index}'
    abi=json.loads(prefix.with_suffix('.ir3.json').read_text());binary=prefix.with_suffix('.bin').read_bytes()
    if sha(binary)!=entry['binary_sha256'] or abi['gpu_executed'] or abi['binary_alignment_bytes']!=128:raise SystemExit('Actual shader identity differs')
    b=abi['binding_state'];isfrag=abi['stage']=='fragment'
    state=State(int(abi['chip_id'],16),4 if isfrag else 0,len(binary),abi['instruction_groups'],abi['max_full_register'],abi['max_half_register'],
        b['branch_stack_hw'],b['merged_registers'],abi['early_preamble'],abi['double_threadsize'],b['input_words'],b['need_full_quad'],b['need_pixel_lod'],abi['private_bytes_per_fiber'],abi['constant_data_bytes'])
    # This is an authored inactive resource view, never an actual allocated
    # hardware address or proof of live GPU SMMU residency/context ownership.
    view=Mapping(1,0x100000000,(len(binary)+4095)&~4095,0,12,1)
    output=(C.c_uint32*128)(*([0x6b6b6b6b]*128));r=bind(C.byref(state),C.byref(view),output,len(output))
    if r.status or r.words!=24 or r.registers!=13:raise SystemExit('Actual variant bind profile refused: '+prefix.name)
    alternate=(C.c_uint32*128)(*([0x6b6b6b6b]*128));state.chip=0xffff43050a01
    alt=bind(C.byref(state),C.byref(view),alternate,len(alternate))
    if alt.status or bytes(alternate)!=bytes(output):raise SystemExit('Full observed identity changed binding')
    decoded={};at=0
    while at<r.words:
        header=output[at];count=header&127;reg=header>>8&0x3ffff
        if header>>28!=4 or count not in (1,2):raise SystemExit('Unexpected A6xx preload/opcode packet')
        for i in range(count):
            if reg+i in decoded:raise SystemExit('Duplicate shader register')
            decoded[reg+i]=output[at+1+i]
        at+=1+count
    stage='PS' if isfrag else 'VS';ctrl='SP_'+stage+'_CNTL_0'
    control=field(ctrl,'FULLREGFOOTPRINT',abi['max_full_register']+1)|field(ctrl,'HALFREGFOOTPRINT',abi['max_half_register']+1)|field(ctrl,'BRANCHSTACK',b['branch_stack_hw'])
    for name,value in [('MERGEDREGS',b['merged_registers']),('EARLYPREAMBLE',abi['early_preamble'])]:control|=field(ctrl,name,int(value))
    if isfrag:
        for name,value in [('THREADSIZE',int(abi['double_threadsize'])),('VARYING',int(b['input_words']!=0)),('LODPIXMASK',int(b['need_full_quad'])),('INOUTREGOVERLAP',1),('PIXLODENABLE',int(b['need_pixel_lod']))]:control|=field(ctrl,name,value)
    # Other required register values follow the exact pinned no-private-memory
    # fd6_emit_shader path. Pipeline/config/linkage state is separate work.
    expected={offset('SP_MODE_CNTL'):field('SP_MODE_CNTL','CONSTANT_DEMOTION_ENABLE',1)|field('SP_MODE_CNTL','ISAMMODE',enums['ISAMMODE_GL']),
              offset('TPL1_MODE_CNTL'):field('TPL1_MODE_CNTL','ISAMMODE',enums['ISAMMODE_GL'])|field('TPL1_MODE_CNTL','NEARESTMIPSNAP',enums['CLAMP_ROUND_TRUNCATE'])|field('TPL1_MODE_CNTL','DESTDATATYPEOVERRIDE',1),
              offset(ctrl):control,offset('SP_'+stage+'_INSTR_SIZE'):abi['instruction_groups'],offset('SP_'+stage+'_PROGRAM_COUNTER_OFFSET'):0,
              offset('SP_'+stage+'_BASE'):view.base&0xffffffff,offset('SP_'+stage+'_BASE')+1:view.base>>32,
              offset('SP_'+stage+'_PVT_MEM_PARAM'):0,offset('SP_'+stage+'_PVT_MEM_BASE'):0,offset('SP_'+stage+'_PVT_MEM_BASE')+1:0,
              offset('SP_'+stage+'_PVT_MEM_SIZE'):0,offset('SP_'+stage+'_PVT_MEM_STACK_OFFSET'):0,offset('SP_'+stage+'_VGS_CNTL'):0}
    if decoded!=expected or at!=24 or bytes(output)[96:]!=b'\x6b'*(len(output)*4-96):raise SystemExit('Actual shader state differs from XML/source oracle')
    encoded=bytes(output)[:96];(OUT/f'{library}-{index}.pm4').write_bytes(encoded)
    results.append(dict(library=library,index=index,stage=abi['stage'],binary_sha256=sha(binary),abi_sha256=sha(prefix.with_suffix('.ir3.json').read_bytes()),
        command_sha256=sha(encoded),command_words=24,registers=13,input_words=b['input_words'],native_page_shift=12,synthetic_inactive_resource_view=True))
(OUT/'report.json').write_text(json.dumps(dict(mesa_revision=REV,source_documents=manifest['files'],unit=unit_result,original_shaders=results,
    source_sha256={p.name:sha(p.read_bytes()) for p in [KIT/"AdrenoPM4.c",KIT/"AdrenoShader.c",KIT/"AdrenoShader.h",KIT/"test_shader.c",ROOT/"kits/AirNir/BackendABI.h"]},
    native_objects={p.name:sha(p.read_bytes()) for p in objects},native_imports=imports,native_archive_sha256=sha(archive.read_bytes()),
    native_cpp_sha256=sha(cpp_obj.read_bytes()),native_linked_module_sha256=sha(native.read_bytes()),
    native_linked_imports=native_imports,ordinary_arm64_ios17=True,
    shader_mapping_or_smmu_activated=False,submission_authorized=False,shader_executed=False,metal_pipeline_or_ui=False),indent=2)+'\n')
print('PASS: 22 actual IR3 vertex/fragment binding states, complete XML register map and native ARM64/iOS17 C/C++ archive + real linked module; no A6xx preload or GPU execution claim')
