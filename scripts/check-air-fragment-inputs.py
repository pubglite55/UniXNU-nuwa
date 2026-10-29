#!/usr/bin/env python3
"""Qualify original smooth-center fragment inputs and post-interpolation arithmetic."""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import random
import re
import struct
import subprocess
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--compiler',type=Path,required=True);p.add_argument('--llvm-bindir',type=Path,required=True);a=p.parse_args()
OUT=ROOT/'build/air-nir/fragment-inputs';OUT.mkdir(parents=True,exist_ok=True)
env={k:v for k,v in os.environ.items() if not k.startswith(('IR3_','FD_MESA_','NIR_','MESA_SHADER_'))};env['IR3_SHADER_DEBUG']='asmroundtrip'
def run(cmd,status=0):
 r=subprocess.run([str(v) for v in cmd],capture_output=True,text=True,env=env,timeout=20)
 if r.returncode!=status:raise RuntimeError(f'Expected {status}, got {r.returncode}: '+r.stderr[-1500:])
 return r
def require(value,why):
 if not value:raise RuntimeError(why)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
reports=[]
for index in (65,67,75,153,155):
 src=ROOT/f'build/gpu-analysis/air/QuartzCore/module-{index}.bc';prefix=OUT/f'QuartzCore-{index}'
 probe=run([a.compiler,src,'0xffff43050a01',prefix,'--compile']);require(json.loads(probe.stdout)['asm_roundtrip'],'Actual assembler roundtrip')
 interface=json.loads(prefix.with_suffix('.interface.json').read_text());abi=json.loads(prefix.with_suffix('.ir3.json').read_text())
 inputs=[i for i in interface['inputs'] if i['kind']=='air.fragment_input'];unused=[i for i in interface['inputs'] if i['kind']=='air.position']
 require(len(unused)==1 and unused[0]['unused'] and unused[0]['components']==4,'Only unused position is accepted')
 text=src.with_suffix('.ll').read_text();identities=re.findall(r'!"air.fragment_input", !"([^"]+)"',text)
 require([i['identity'] for i in inputs]==identities and [i['index'] for i in inputs]==list(range(len(inputs))) and all(i['interpolation']=='perspective' and i['sampling']=='center' for i in inputs),'Exact original varying identities, dense slots and qualifiers')
 actual={i['slot']:i for i in abi['inputs'] if not i['system_value']}
 require(set(actual)=={32+i['index'] for i in inputs} and all(actual[32+i['index']]['component_mask']==(1<<i['components'])-1 and not actual[32+i['index']]['half'] for i in inputs),'Actual IR3 varying slot/component allocation')
 require(len([i for i in abi['inputs'] if i['system_value']])==1 and not abi['writes_position'] and abi['stage']=='fragment','Actual barycentric system value, no fabricated position')
 inwords=max(i['inloc']+i['component_mask'].bit_length() for i in actual.values())
 require(abi['binding_state']['input_words']==inwords,'Actual padded input footprint retained')
 nir=prefix.with_suffix('.nir').read_text();require('load_barycentric_pixel' in nir and 'load_interpolated_input' in nir and 'perspective_varyings:' in nir,'Real NIR interpolation inputs')
 rng=random.Random(740000+index);frames=[];values=[]
 special=[0,0x80000000,0x3f800000,0x3f000000,0xbf800000,0x40000000,1,0x80000001,0x007fffff,0x00800000,0x7f7fffff,0xff7fffff]
 for case in range(4096):
  words=[]
  for slot in range(16*4):
   bits=special[(case+slot)%len(special)] if case<128 else rng.getrandbits(32)
   if (bits>>23)&255==255:bits^=1<<23
   words.append(bits)
  values.append(words);frames.append(struct.pack('<I64I',case,*words))
 casepath=prefix.with_suffix('.cases');casepath.write_bytes(b''.join(frames))
 run([a.compiler,src,'0xffff43050a01',prefix,'--compile','--test-resources',casepath])
 oracle=prefix.with_suffix('.oracle.bc');run([a.compiler,src,'0xffff43050a01',oracle,'--test-resource-oracle'])
 dylib=prefix.with_suffix('.dylib');run([a.llvm_bindir/'clang','-O2','-dynamiclib',oracle,'-o',dylib])
 library=C.CDLL(str(dylib));fn=library.air_test_resource_oracle;fn.argtypes=[C.c_void_p,C.c_void_p,C.c_uint32,C.c_void_p]
 actual_bytes=prefix.with_suffix('.eval').read_bytes();slots=len(interface['outputs']);require(len(actual_bytes)==4096*slots*16,'Exact native NIR numerical result framing')
 for case,words in enumerate(values):
  data=(C.c_uint32*64)(*words);expected=(C.c_uint32*(slots*4))();fn(data,None,0,expected)
  got=struct.unpack_from('<'+'I'*(slots*4),actual_bytes,case*slots*16)
  for output in interface['outputs']:
   for component in range(output['components']):
    lane=output['slot']*4+component;x,y=got[lane],expected[lane]
    require(x==y or (x&0x7fffffff)==0 and (y&0x7fffffff)==0,f'Original AIR/NIR finite result differs: {index}/{case}/{lane}: {x:08x}!={y:08x}')
 reports.append(dict(library='QuartzCore',index=index,stage='fragment',post_interpolation_cases=4096,
     original_bitcode_sha256=sha(src),binary_sha256=sha(prefix.with_suffix('.bin')),interface_sha256=sha(prefix.with_suffix('.interface.json')),
     abi_sha256=sha(prefix.with_suffix('.ir3.json')),varying_identities=identities,input_words=inwords,
     assembler_roundtrip=True,hardware_interpolation_qualified=False))
 print('PASS:',index,'4096 original-IR/NIR post-interpolation cases; true IR3 barycentric input and exact source identities',flush=True)
original=(ROOT/'build/gpu-analysis/air/QuartzCore/module-75.ll').read_text()
mutations={
 'centroid':original.replace('!"generated(5colorDv4_f)", !"air.center"','!"generated(5colorDv4_f)", !"air.centroid"'),
 'linear':original.replace('!"generated(5colorDv4_f)", !"air.center", !"air.perspective"','!"generated(5colorDv4_f)", !"air.center", !"air.no_perspective"'),
 'flat':original.replace('!"generated(5colorDv4_f)", !"air.center", !"air.perspective"','!"generated(5colorDv4_f)", !"air.center", !"air.flat"'),
 'missing-identity':original.replace('generated(5colorDv4_f)','unknown(color)'),
 'unterminated-identity':original.replace('generated(5colorDv4_f)','generated(5colorDv4_f'),
 'duplicate-identity':original.replace('generated(7dist_CDf)','generated(5colorDv4_f)'),
 'strict-saturate':original.replace('call fast float @air.fast_saturate.f32','call float @air.fast_saturate.f32',1),
 'zero-sign-saturate':original.replace('call fast float @air.fast_saturate.f32','call nnan ninf float @air.fast_saturate.f32',1),
 'used-position':original.replace('  %7 = tail call fast float @air.fast_saturate.f32(float %2)', '  %p = extractelement <4 x float> %0, i64 0\n  %7 = tail call fast float @air.fast_saturate.f32(float %p)'),
 'declared-used-position':original.replace(', !"air.arg_unused"',''),
 'half-input':original.replace('float %2, float %3','half %2, float %3').replace('@air.fast_saturate.f32(float %2)','@air.fast_saturate.f32(float 5.000000e-01)'),
}
for name,text in mutations.items():
 require(text!=original,'Mutation must change input '+name)
 ll,bc,prefix=OUT/(name+'.ll'),OUT/(name+'.bc'),OUT/name;ll.write_text(text);run([a.llvm_bindir/'llvm-as',ll,'-o',bc]);prefix.with_suffix('.bin').unlink(missing_ok=True)
 run([a.compiler,bc,'0xffff43050a01',prefix,'--compile'],4);require(not prefix.with_suffix('.bin').exists(),'Refusal exported GPU code')
(OUT/'report.json').write_text(json.dumps(dict(originals=reports,refusals=len(mutations),gpu_execution=False,hardware_interpolation=False,cpu_rasterizer=False),indent=2)+'\n')
print('PASS:',len(mutations),'interpolation, identity, position and per-instruction math refusals; no GPU interpolation claim')
