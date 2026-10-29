#!/usr/bin/env python3
"""Derive the genuine original abstract IOGPU provider and required dispatch ABI."""
import hashlib,json,runpy,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
n=runpy.run_path(str(ROOT/'scripts/audit-target-accelerator-base.py'));read,require,adrp=n['read'],n['require'],n['adrp'];code,text=n['code'],n['text']
runtime_path=ROOT/'build/darwinboot-owner-hvf-iogpu-gpu-class/gdb-stop.json';runtime=json.loads(runtime_path.read_text());args=[int(v,16) for v in runtime['function_entry_arguments']];meta=args[0]
require(runtime['function_return_stack_matched'] and runtime['entry_kernel_bytes_match']['bytes']==b'IOGPU\0'.hex() and args[3]==736 and args[2]==int(n['meta']),'Previously observed actual 736-byte IOGPU and original accelerator parent')
getters=[]
for i in range(0,len(code)-12,4):
 pc=text['va']+i;a,b,c=struct.unpack_from('<3I',code,i)
 if a&0x9f00001f==0x90000000 and b&0xffc003ff==0x91000000 and c==0xd65f03c0 and adrp(pc,a)+((b>>10)&4095)==meta:getters.append(pc)
require(len(getters)==1,'Unique actual original IOGPU getMetaClass')
base=struct.unpack('<168Q',read(n['vp'],168*8));tables=[]
for e in n['es']:
 if e['segment']=='__TEXT_EXEC':continue
 data=read(e['va'],e['size']);at=0
 while True:
  pos=data.find(struct.pack('<Q',getters[0]),at)
  if pos<0:break
  at=pos+1;vp=e['va']+pos-56
  if vp%8:continue
  v=struct.unpack('<256Q',read(vp,2048));count=next(i for i,a in enumerate(v) if not a);diff=[i for i,(a,b) in enumerate(zip(base,v)) if a!=b]
  if count==215 and diff==[0,1,7,14,81,82,86,87,111,141]:tables.append((vp,v[:count]))
require(len(tables)==1,'Unique original 215-entry provider table and exact native service prefix')
vp,values=tables[0];pure=[i for i,a in enumerate(values) if a==n['names']['___cxa_pure_virtual']]
require(pure==[170,174,189,192,195,196,197,200,202,205],'All ten original pure callbacks, no invented complete provider')
constructors=[]
for i in range(12,len(code)-20,4):
 pc=text['va']+i;a,b,c=struct.unpack_from('<3I',code,i)
 if a&0x9f00001f!=0x90000008 or b&0xffc003ff!=0x91000108 or c!=0xf9000008 or adrp(pc,a)+((b>>10)&4095)!=vp:continue
 start=pc-12;w=struct.unpack('<8I',read(start,32))
 if w[:2]!=(0xa9bf7bfd,0x910003fd) or w[-2:]!=(0xa8c17bfd,0xd65f03c0):continue
 require(n['imported'](n['branch'](start+8))==n['names']['__ZN9IOServiceC2EPK11OSMetaClass'],'Original protected constructor inlines empty accelerator base and calls genuine native service C2');constructors.append(start)
require(len(constructors)==1,'Unique original abstract protected constructor')
protected_destructor=constructors[0]+32
require(n['imported'](n['branch'](protected_destructor))==n['names']['__ZN9IOServiceD2Ev'],'Actual protected base D2 delegates to genuine native service D2')
require(read(values[0],8)==struct.pack('<2I',0xd4200020,0xd4200020) and values[1]==values[0]+4,'Original abstract D1/D0 are genuine BRK traps, not usable protected D2 aliases')
reference_meta_vp=n['names']['__ZTVN9IOService9MetaClassE']+16;reference_alloc=n['names']['__ZNK9IOService9MetaClass5allocEv'];reference_table=struct.unpack('<32Q',read(reference_meta_vp,256));slots=[i for i,a in enumerate(reference_table) if a==reference_alloc]
require(slots==[13],'Actual native metaclass allocation virtual position')
pc=int(runtime['pc'],16);a,b,c=struct.unpack('<3I',read(pc,12));require(a&0x9f00001f==0x90000008 and b&0xffc003ff==0x91000108 and c==0xf9000008,'Observed original metaclass constructor return installs its actual own table')
meta_vp=adrp(pc,a)+((b>>10)&4095);allocate=struct.unpack('<Q',read(meta_vp+13*8,8))[0]
require(read(allocate,8)==struct.pack('<2I',0xd2800000,0xd65f03c0),'Original abstract IOGPU factory genuinely returns NULL; do not force an abstract allocation')
start,end=values[86],values[87];body=read(start,end-start);words=struct.unpack('<'+'I'*(len(body)//4),body)
require(words[8:10]==(0xaa0103f4,0xaa0003f3),'Original start preserves actual provider in x20 and this in x19')
calls=[]
for i,w in enumerate(words):
 if w!=0xf9400268:continue # LDR x8,[x19]: genuine preserved this vptr.
 load=words[i+1]
 if load&0xffc003ff!=0xf9400108:continue
 slot=(load>>10)&4095
 if any(v==0xd63f0100 for v in words[i+2:min(i+8,len(words))]):calls.append(dict(pc=start+4*i,slot=slot))
first=next(v for v in calls if v['slot'] in pure);at=(first['pc']-start)//4
require(first['slot']==195 and tuple(words[at+2:at+5])==(0xaa1303e0,0xaa1403e1,0xd63f0100) and words[at+5]&0xff00001f==0x36000000,'First required pure hook gets genuine this/provider and its actual Boolean result is checked before proceeding')
report=dict(reference_candidate_sha256=n['plan']['candidate_sha256'],original_iogpu_text_sha256=n['plan']['original_executable_sha256']['com.apple.iokit.IOGPUFamily'],runtime_class_evidence_sha256=hashlib.sha256(runtime_path.read_bytes()).hexdigest(),metaclass=meta,instance_bytes=736,parent_bytes=136,vptr=vp,virtual_entries=215,pure_virtual_slots=pure,operational_overrides=[14,81,82,86,87,111,141],inherited_entries=list(values),protected_constructor=constructors[0],protected_destructor=protected_destructor,abstract_destructor_traps=list(values[:2]),metaclass_vptr=meta_vp,abstract_factory=allocate,original_factory_returns_null=True,start=start,start_bytes=len(body),start_sha256=hashlib.sha256(body).hexdigest(),self_virtual_dispatches=calls,first_required_dispatch=first,first_required_register_abi=dict(this='x0',provider='x1',result='w0 bit 0'),opaque_tail_source_signatures_qualified=False,metadata_only=True,provider_instance_qualified=False,normal_system_authorization=False,original_desktop=False,adreno_execution=False)
(ROOT/'build/gpu-analysis/original-iogpu-provider-abi.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: actual abstract 736-byte/215-entry IOGPU, ten pure callbacks, genuine NULL factory and first required this/provider Boolean hook 195')
print('Private tail source signatures, provider construction/start and ordinary system authorization remain unqualified')
