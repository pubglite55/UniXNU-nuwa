#!/usr/bin/env python3
"""Compare the native raster encoder with Mesa's actual A740 state function."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'build/adreno-raster';OUT.mkdir(parents=True,exist_ok=True)
KIT=ROOT/'kits/AdrenoPM4';MESA=ROOT/'.cache/mesa-work'
HEAD='85fda3b36405bcaea8bffc64aa4f2651dc90770d'
def run(cmd,**kwargs):
    return subprocess.check_output([str(x) for x in cmd],timeout=60,**kwargs)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def require(v,why):
    if not v:raise SystemExit(why)
require(run(['git','-C',MESA,'rev-parse','HEAD'],text=True).strip()==HEAD,'Pinned Mesa source')
pins=json.loads((ROOT/'scripts/data/adreno-raster-inputs.json').read_text())
sources={}
for name,digest in pins['files'].items():
    content=run(['git','-C',MESA,'show',HEAD+':'+name])
    require(hashlib.sha256(content).hexdigest()==digest,'Pinned primary input '+name)
    if (MESA/name).exists():require(sha(MESA/name)==digest,'Working reference unchanged '+name)
    sources[name]=content.decode()
for name in ('adreno_common','adreno_pm4','a6xx_enums','a7xx_enums','a8xx_enums','a6xx'):
    generated=run([ROOT/'.cache/mesa-venv/bin/python',MESA/'src/freedreno/registers/gen_header.py','--rnn',MESA/'src/freedreno/registers','--xml',MESA/'src/freedreno/registers/adreno'/(name+'.xml'),'c-defines'],env=dict(os.environ,PYTHONHASHSEED='0'))
    (OUT/(name+'.xml.h')).write_bytes(generated)
(OUT/'a6xx-pack.xml.h').write_bytes(run([ROOT/'.cache/mesa-venv/bin/python',MESA/'src/freedreno/registers/gen_header.py','--rnn',MESA/'src/freedreno/registers','--xml',MESA/'src/freedreno/registers/adreno/a6xx.xml','c-pack-structs'],env=dict(os.environ,PYTHONHASHSEED='0')))
def function(text,name):
    match=re.search(r'static inline (?:float|bool)\n'+re.escape(name)+r'\(',text)
    require(match,'Exact primary helper '+name)
    start=text.index('{',match.start());end=start+1;depth=1
    while depth:
        require(end<len(text),'Bounded primary helper')
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[match.start():end]+'\n'
raster=sources['src/gallium/drivers/freedreno/a6xx/fd6_rasterizer.cc']
start=raster.index('template <chip CHIP>');end=raster.index('\nFD_GENX(__fd6_setup_rasterizer_stateobj);',start)
actual_function=raster[start:end]+'\n'
reference=OUT/'reference.cpp'
reference.write_text('''#include <cassert>
#include <cstdint>
#include <cstring>
#include "pipe/p_state.h"
#include "util/half_float.h"
#include "util/u_math.h"
#include "AdrenoRaster.h"
#include "adreno_common.xml.h"
#include "adreno_pm4.xml.h"
#include "a6xx_enums.xml.h"
#include "a7xx_enums.xml.h"
#include "a8xx_enums.xml.h"
#include "a6xx.xml.h"
struct fd_reg_pair {uint32_t reg;uint64_t value;void *bo;bool is_address;uint32_t bo_offset,bo_shift,bo_low;};
#define __bo_type void *
#include "a6xx-pack.xml.h"
// Only the transport is replaced: collect actual register/value pairs.
struct fd_ringbuffer {unsigned count;uint32_t reg[64],value[64];};
struct ref_props {bool is_a702,has_legacy_pipeline_shading_rate;};
struct ref_info {ref_props props;};struct ref_screen {ref_info *info;};
struct fd_context {fd_ringbuffer *pipe;ref_screen *screen;};
struct fd_crb {fd_ringbuffer *ring;
    fd_crb(fd_ringbuffer *r,unsigned) : ring(r) {ring->count=0;}
    fd_crb &add(fd_reg_pair pair) {assert(ring->count<64 && !pair.bo && !pair.is_address && pair.value<=UINT32_MAX);unsigned n=ring->count++;ring->reg[n]=pair.reg;ring->value[n]=(uint32_t)pair.value;return *this;}
    operator fd_ringbuffer *() {return ring;}
};
#define assert_dt
'''+function(sources['src/gallium/auxiliary/util/u_inlines.h'],'util_get_min_point_size')+
    function(sources['src/gallium/drivers/freedreno/freedreno_state.h'],'fd_rast_depth_clamp_enabled')+actual_function+'''
static float raw_float(uint32_t bits) {float value;memcpy(&value,&bits,4);return value;}
extern "C" size_t AdrenoRasterReference(const AdrenoRasterState *,uint32_t *,uint32_t *,size_t);
extern "C" size_t AdrenoRasterReference(const AdrenoRasterState *s,uint32_t *regs,uint32_t *values,size_t capacity) {
    pipe_rasterizer_state cso={};uint32_t f=s->flags;
    cso.depth_clip_near=f&AdrenoRasterClipNear;cso.depth_clip_far=(f&AdrenoRasterClipFar)!=0;
    cso.clip_halfz=(f&AdrenoRasterHalfZ)!=0;cso.cull_face=((f&AdrenoRasterCullFront)?PIPE_FACE_FRONT:0)|((f&AdrenoRasterCullBack)?PIPE_FACE_BACK:0);
    cso.front_ccw=(f&AdrenoRasterFrontCCW)!=0;cso.offset_tri=(f&AdrenoRasterOffsetTriangles)!=0;
    cso.multisample=(f&AdrenoRasterMultisample)!=0;cso.flatshade_first=(f&AdrenoRasterFlatFirst)!=0;
    cso.point_size_per_vertex=(f&AdrenoRasterPointSizePerVertex)!=0;
    cso.point_quad_rasterization=(f&AdrenoRasterPointQuad)!=0;cso.point_smooth=(f&AdrenoRasterPointSmooth)!=0;
    cso.fill_front=s->polygon_mode==1?PIPE_POLYGON_MODE_POINT:s->polygon_mode==2?PIPE_POLYGON_MODE_LINE:PIPE_POLYGON_MODE_FILL;
    cso.point_size=s->point_size_q4/16.0f;cso.line_width=s->line_width_q1/2.0f;
    cso.offset_scale=raw_float(s->offset_scale_bits);cso.offset_units=raw_float(s->offset_units_bits);cso.offset_clamp=raw_float(s->offset_clamp_bits);
    fd_ringbuffer ring={};fd_context ctx={&ring,nullptr};
    assert(__fd6_setup_rasterizer_stateobj<A7XX>(&ctx,&cso,(f&AdrenoRasterPrimitiveRestart)!=0)==&ring);
    assert(ring.count<=capacity);memcpy(regs,ring.reg,ring.count*4);memcpy(values,ring.value,ring.count*4);return ring.count;
}
''')
build=ROOT/'build/mesa-ir3'
commands=run(['ninja','-C',build,'-t','commands','src/freedreno/ir3/air_nir'],text=True).splitlines()
base=next(shlex.split(x) for x in commands if shlex.split(x)[-1]==str(ROOT/'kits/AirNir/MesaBackend.c'))
for flag in ('-MQ','-MF'):
    i=base.index(flag);del base[i:i+2]
base=[x for x in base if x not in ('-MD',)]
base[1:1]=['-DMESA_REFERENCE','-DFD_NO_DEPRECATED_PACK','-fsanitize=address,undefined','-I'+str(KIT),'-I'+str(OUT),'-I'+str(MESA/'src/gallium/include')]
objects=[]
for name,path in (('test',KIT/'test_raster.c'),('raster',KIT/'AdrenoRaster.c'),('pm4',KIT/'AdrenoPM4.c'),('reference',reference)):
    cmd=base.copy();obj=OUT/(name+'.o');cmd[cmd.index('-o')+1]=str(obj);cmd[-1]=str(path)
    if name=='reference':
        cmd[0]=str(Path(cmd[0]).with_name('clang++'));cmd=[x for x in cmd if not x.startswith('-std=')];cmd[1:1]=['-std=c++20','-Wno-c99-designator','-Wno-c++11-narrowing','-Wno-missing-field-initializers']
    run(cmd,cwd=build);objects.append(obj)
exe=OUT/'test-reference';run(['xcrun','clang++','-fsanitize=address,undefined',*objects,'-o',exe])
unit=run([exe],text=True).strip();print(unit)
require(unit=='PASS: 114916 raster profiles, 41 transactional refusals','Exact source-reference suite inventory')
import sys
import struct
sys.path.insert(0,str(ROOT/'kits/XnuPrelink'))
from native_prelink import macho
sdk=run(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
objects=[]
for name in ('AdrenoPM4','AdrenoConstants','AdrenoShader','AdrenoVPC','AdrenoRaster'):
    obj=OUT/(name+'.ios.o')
    run(['xcrun','clang','-target','arm64-apple-ios17.0','-isysroot',sdk,'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fstack-protector-strong','-c',KIT/(name+'.c'),'-o',obj])
    raw=obj.read_bytes();parsed=macho(raw)
    require(parsed['kind']==1 and [struct.unpack_from('<II',raw,p+8) for cmd,p,_ in parsed['commands'] if cmd==0x32]==[(2,0x110000)],'Actual ordinary ARM64/iOS17 object')
    objects.append(obj)
cpp=OUT/'client.cpp';cpp.write_text('#include "AdrenoRaster.h"\nstatic_assert(sizeof(AdrenoRasterState)==40 && sizeof(AdrenoRasterResult)==12);\nextern "C" unsigned client(const AdrenoRasterState *s,unsigned *o){return AdrenoA740Raster(s,o,60).status;}\n')
client=OUT/'client.ios.o';run(['xcrun','clang++','-target','arm64-apple-ios17.0','-isysroot',sdk,'-std=c++17','-O2','-Wall','-Wextra','-Werror','-I',KIT,'-c',cpp,'-o',client])
native=OUT/'AdrenoPipeline.ios.dylib';run(['xcrun','clang','-target','arm64-apple-ios17.0','-isysroot',sdk,'-dynamiclib',client,*objects,'-Wl,-undefined,error','-o',native])
imports=run(['xcrun','nm','-u',native],text=True).split()
require(set(imports)<=set(['___stack_chk_fail','___stack_chk_guard','dyld_stub_binder']),'Actual complete helper link without missing symbols')
(OUT/'report.json').write_text(json.dumps(dict(mesa_revision=HEAD,
    kit_revision=run(['git','-C',KIT,'rev-parse','HEAD'],text=True).strip(),
    source_sha256={str(p.relative_to(ROOT)):sha(p) for p in (KIT/'AdrenoRaster.c',KIT/'AdrenoRaster.h',KIT/'test_raster.c')},
    primary_function_sha256=hashlib.sha256(actual_function.encode()).hexdigest(),
    generated_reference_sha256=sha(reference),primary_manifest_sha256=sha(ROOT/'scripts/data/adreno-raster-inputs.json'),
    generated_header_sha256={p.name:sha(p) for p in sorted(OUT.glob('*.xml.h'))},
    native_link_sha256=sha(native),native_link_imports=imports,
    unit=unit,actual_primary_function=True,transport_replaced_by_register_collector=True,
    gpu_execution=False,active_gpu_smmu_qualified=False,complete_pipeline_state=False),indent=2)+'\n')
print('PASS: every encoded raster register matches the actual pinned A740 rasterizer function')
