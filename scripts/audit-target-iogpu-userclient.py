#!/usr/bin/env python3
"""Derive the original concrete IOGPU userclient lifecycle without publishing it."""
import hashlib,json,runpy,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
n=runpy.run_path(str(ROOT/'scripts/audit-target-accelerator-base.py'))
read,require,adrp=n['read'],n['require'],n['adrp'];code,text=n['code'],n['text'];plan=n['plan']
runtime_path=ROOT/'build/darwinboot-owner-hvf-iogpu-userclient-class/gdb-stop.json';runtime=json.loads(runtime_path.read_text())
args=[int(v,16) for v in runtime['function_entry_arguments']];meta=args[0];parent=bytes.fromhex(runtime['entry_regions']['2:0:80']['bytes'])
require(runtime['function_return_stack_matched'] and runtime['entry_kernel_bytes_match']['bytes']==b'IOGPUDeviceUserClient\0'.hex() and args[3]==304 and struct.unpack_from('<I',parent,32)[0]==216,'Previously observed real original class/parent extents, not an invented class layout')
current=ROOT/'build/xnu-prelink/native-owner-metal-shared-events-candidate.json';current_plan=json.loads(current.read_text())
require(current_plan['original_executable_sha256']['com.apple.iokit.IOGPUFamily']==plan['original_executable_sha256']['com.apple.iokit.IOGPUFamily'],'Current candidate preserves the exact same complete original IOGPU executable')
getters=[]
for i in range(0,len(code)-12,4):
 a,b,c=struct.unpack_from('<3I',code,i);pc=text['va']+i
 if a&0x9f00001f==0x90000000 and b&0xffc003ff==0x91000000 and c==0xd65f03c0 and adrp(pc,a)+((b>>10)&4095)==meta:getters.append(pc)
require(len(getters)==1,'Unique original userclient getMetaClass')
baseva=n['names']['__ZTV12IOUserClient']+16;base=struct.unpack('<256Q',read(baseva,2048));base_count=next(i for i,v in enumerate(base) if not v)
require(base_count==186,'Actual native reference IOUserClient vtable extent')
tables=[]
for e in n['es']:
 if e['segment']=='__TEXT_EXEC':continue
 raw=read(e['va'],e['size']);at=0
 while True:
  pos=raw.find(struct.pack('<Q',getters[0]),at)
  if pos<0:break
  at=pos+1;vp=e['va']+pos-56
  if vp%8:continue
  values=struct.unpack('<256Q',read(vp,2048));count=next(i for i,v in enumerate(values) if not v)
  differences=[i for i in range(min(base_count,count)) if values[i]!=base[i]]
  if count==189 and differences==[0,1,7,14,86,87,168,169,172,185]:tables.append((vp,values[:count]))
require(len(tables)==1,'Unique original 189-entry operational userclient table and exact inherited prefix')
vp,values=tables[0];constructors=[]
for i in range(12,len(code)-20,4):
 a,b,c=struct.unpack_from('<3I',code,i);pc=text['va']+i
 if a&0x9f00001f!=0x90000008 or b&0xffc003ff!=0x91000108 or c!=0xf9000008 or adrp(pc,a)+((b>>10)&4095)!=vp:continue
 start=pc-12;words=struct.unpack('<8I',read(start,32))
 if words[0:2]!=(0xa9bf7bfd,0x910003fd) or words[6:8]!=(0xa8c17bfd,0xd65f03c0):continue
 require(n['imported'](n['branch'](start+8))==n['names']['__ZN12IOUserClientC2EPK11OSMetaClass'],'Real protected constructor calls genuine native IOUserClient C2')
 constructors.append(start)
require(len(constructors)==2 and n['imported'](n['branch'](values[0]))==n['names']['__ZN12IOUserClientD2Ev'],'Two original protected constructors and genuine non-deleting destructor chain')
free=read(values[14],256);words=struct.unpack('<64I',free);tail=next(i for i,v in enumerate(words) if v==0xd61f0020);free=free[:4*(tail+1)]
guards=[]
for i in range(tail):
 a,b=words[i:i+2]
 if a&0xffc003ff==0xf9400260 and b&0xff00001f==0xb4000000:guards.append(((a>>10)&4095)*8)
 # The first load uses x0 rather than the preserved x19.
 if a&0xffc003ff==0xf9400000 and b&0xff00001f==0xb4000000:guards.append(((a>>10)&4095)*8)
 if a&0xffc003ff==0xf9400268 and b&0xff00001f==0xb4000008:guards.append(((a>>10)&4095)*8)
require(guards==[288,272,264,216,240],'Original free genuinely guards every uninitialized private pointer before cleanup')
start=read(values[86],108);sw=struct.unpack('<27I',start)
require(sw[10]&0x9f00001f==0x90000008 and sw[11]&0xffc003ff==0x91000108 and sw[12]==0xf9400101,'Original start loads its genuine provider metaclass')
provider_meta=struct.unpack('<Q',read(adrp(values[86]+40,sw[10])+((sw[11]>>10)&4095),8))[0]
gpu_runtime=json.loads((ROOT/'build/darwinboot-owner-hvf-iogpu-gpu-class/gdb-stop.json').read_text());require(provider_meta==int(gpu_runtime['function_entry_arguments'][0],16),'Original start requires the actually observed IOGPU provider class')
require(sw[15]==0xf9007e60 and sw[16]&0xff00001f==0xb4000000 and sw[18]==0xf942e908,'Actual provider cast must succeed before original extra virtual initialization at slot 186')
report=dict(reference_candidate_sha256=plan['candidate_sha256'],current_candidate_sha256=current_plan['candidate_sha256'],original_iogpu_text_sha256=plan['original_executable_sha256']['com.apple.iokit.IOGPUFamily'],runtime_class_evidence_sha256=hashlib.sha256(runtime_path.read_bytes()).hexdigest(),metaclass=hex(meta),instance_bytes=304,parent_instance_bytes=216,vptr=hex(vp),virtual_entries=189,operational_overrides=[14,86,87,168,169,172,185],extra_virtual_entries=[186,187,188],constructors=[hex(v) for v in constructors],destructor=hex(values[0]),free=hex(values[14]),free_bytes=len(free),zero_private_pointer_guards=guards,start=hex(values[86]),required_provider_metaclass=hex(provider_meta),entry_sha256={name:hashlib.sha256(raw).hexdigest() for name,raw in [('free',free),('start',start),*(('constructor_'+str(i),read(va,32)) for i,va in enumerate(constructors))]},metadata_only=True,native_original_client_instance_qualified=False,original_authorization_qualified=False,system_metal=False,original_desktop=False)
(ROOT/'build/gpu-analysis/original-iogpu-userclient-abi.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: genuine original 304-byte/189-entry IOGPU userclient C2/D2/free and mandatory real IOGPU provider; no runtime instance or authorization claimed')
