#!/usr/bin/env python3
"""Derive the exact original IOAcceleratorES base ABI without publishing a device."""
import hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'kits/XnuPrelink'))
from native_prelink import macho,backed_offset,exports
def require(v,s):
 if not v:raise SystemExit(s)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
p=ROOT/'build/xnu-prelink/native-owner-renderbox-presentation-candidate.macho';plan=json.loads(p.with_suffix('.json').read_text());raw=p.read_bytes();im=macho(raw)
require(sha(p)==plan['candidate_sha256'],'Exact immutable candidate')
def read(a,n):
 at=backed_offset(im['segments'],a,n,len(raw));return raw[at:at+n]
def adrp(pc,word):
 imm=((word>>5)&0x7ffff)*4+((word>>29)&3)
 if imm&(1<<20):imm-=1<<21
 return (pc&~4095)+(imm<<12)
def branch(pc):
 w=struct.unpack('<I',read(pc,4))[0];require(w&0x7c000000==0x14000000,'Actual direct branch')
 imm=w&0x3ffffff;return pc+4*(imm-(1<<26) if imm&(1<<25) else imm)
def imported(stub):
 a,b,c=struct.unpack('<3I',read(stub,12));require(a&0x9f00001f==0x90000010 and b&0xffc003ff==0xf9400210 and c==0xd61f0200,'Actual ARM64 import stub')
 return struct.unpack('<Q',read(adrp(stub,a)+((b>>10)&4095)*8,8))[0]
names={n:a for a,group in exports(raw,im).items() for n in group}
runtime_path=ROOT/'build/darwinboot-owner-hvf-iogpu-gpu-class/gdb-stop.json';runtime=json.loads(runtime_path.read_text());parent=bytes.fromhex(runtime['entry_regions']['2:0:80']['bytes']);meta=int(runtime['function_entry_arguments'][2],16)
require(runtime['function_return_stack_matched'] and meta==0xfffffff006aeb688 and struct.unpack_from('<I',parent,32)[0]==136 and
 runtime['entry_kernel_bytes_match']['bytes']==b'IOGPU\0'.hex(),'Previously observed actual original parent class metadata, not an invented ancestry')
name=struct.unpack_from('<Q',parent,24)[0];require(read(name,16)==b'IOAcceleratorES\0','Actual original parent name')
es=[e for e in plan['extents'] if e['module']=='com.apple.iokit.IOGPUFamily'];text=next(e for e in es if e['segment']=='__TEXT_EXEC');code=read(text['va'],text['size'])
require(hashlib.sha256(code).hexdigest()==plan['original_executable_sha256']['com.apple.iokit.IOGPUFamily'],'Complete original IOGPU executable unchanged')
getters=[]
for i in range(0,len(code)-12,4):
 a,b,c=struct.unpack_from('<3I',code,i);pc=text['va']+i
 if a&0x9f00001f==0x90000000 and b&0xffc003ff==0x91000000 and c==0xd65f03c0 and adrp(pc,a)+((b>>10)&4095)==meta:getters.append(pc)
require(len(getters)==1,'Unique exact original getMetaClass body')
base=struct.unpack('<168Q',read(names['__ZTV9IOService']+16,168*8));tables=[]
for e in es:
 if e['segment']=='__TEXT_EXEC':continue
 data=read(e['va'],e['size']);at=0
 while True:
  i=data.find(struct.pack('<Q',getters[0]),at)
  if i<0:break
  at=i+1;vp=e['va']+i-7*8
  if vp%8:continue
  v=struct.unpack('<168Q',read(vp,168*8));diff=[j for j,(a,b) in enumerate(zip(base,v)) if a!=b]
  if diff==[0,1,7] and read(vp+168*8,24)==bytes(24):tables.append((vp,v))
require(len(tables)==1,'Unique exact 168-entry original service ABI; only destructor/metaclass overrides')
vp,v=tables[0];constructors=[]
for i in range(0,len(code)-12,4):
 pc=text['va']+i;a,b,c=struct.unpack_from('<3I',code,i)
 if a&0x9f00001f!=0x90000008 or b&0xffc003ff!=0x91000108 or c!=0xf9000008 or adrp(pc,a)+((b>>10)&4095)!=vp:continue
 start=pc-12;w=struct.unpack('<8I',read(start,32))
 require(w[0]==0xa9bf7bfd and w[1]==0x910003fd and w[6]==0xa8c17bfd and w[7]==0xd65f03c0 and
  imported(branch(start+8))==names['__ZN9IOServiceC2EPK11OSMetaClass'],'Exact constructor only calls genuine IOService C2 and installs its own vptr')
 constructors.append(start)
require(len(constructors)==2 and imported(branch(v[0]))==names['__ZN9IOServiceD2Ev'],'Both identical constructor aliases and real non-deleting destructor chain')
report=dict(candidate_sha256=plan['candidate_sha256'],original_iogpu_text_sha256=hashlib.sha256(code).hexdigest(),runtime_parent_evidence_sha256=sha(runtime_path),
 metaclass=hex(meta),instance_bytes=136,vptr=hex(vp),virtual_entries=168,operational_overrides=[],metadata_overrides=[0,1,7],
 protected_compatible_constructor_aliases=[hex(a) for a in constructors],nondeleting_destructor=hex(v[0]),get_meta_class=hex(getters[0]),
 original_entry_sha256={hex(a):hashlib.sha256(read(a,32)).hexdigest() for a in (*constructors,v[0],getters[0])},
 native_iogpu_instance_created=False,system_device_published=False,system_metal=False,original_desktop=False)
(ROOT/'build/gpu-analysis/ioaccelerator-base-abi.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: exact original IOAcceleratorES is a 136-byte, 168-entry IOService base with no operational overrides; real C2/D2 chains derived')
print('Static/runtime-parent metadata evidence only: no accelerator instance, normal Metal device or desktop created')
