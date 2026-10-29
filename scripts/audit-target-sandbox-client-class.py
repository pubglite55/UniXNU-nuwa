#!/usr/bin/env python3
"""Derive the supplied original Sandbox I/O Kit hook and genuine class walk."""
import hashlib,json,re,runpy,struct,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
n=runpy.run_path(str(ROOT/'scripts/audit-target-accelerator-base.py'))
read,require=n['read'],n['require']
es=[e for e in n['plan']['extents'] if e['module']=='com.apple.security.sandbox']
text=next(e for e in es if e['segment']=='__TEXT_EXEC');code=read(text['va'],text['size'])
digest=hashlib.sha256(code).hexdigest()
require(digest==n['plan']['original_executable_sha256']['com.apple.security.sandbox'],'Exact complete supplied original Sandbox executable')
obj=ROOT/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/security/DEVELOPMENT/mac_vfs.o'
layouts={}
for typename,fields in (('mac_policy_conf',('mpc_name','mpc_fullname','mpc_ops')),('mac_policy_ops',('mpo_iokit_check_open','mpo_iokit_check_open_service'))):
 dwarf=subprocess.check_output(['xcrun','dwarfdump','--name='+typename,'--show-children',obj],text=True)
 layouts[typename]={}
 for field in fields:
  match=re.search(r'DW_AT_name\s+\("'+field+r'"\)[\s\S]*?DW_AT_data_member_location\s+\((0x[0-9a-f]+)\)',dwarf)
  require(match,'Actual compiled MAC policy field '+field);layouts[typename][field]=int(match[1],16)
def q(a):return struct.unpack('<Q',read(a,8))[0]
strings=[]
for e in es:
 if e['segment']!='__TEXT':continue
 data=read(e['va'],e['size']);at=0
 while (at:=data.find(b'Sandbox\0',at))>=0:strings.append(e['va']+at);at+=1
confs=[];fields=layouts['mac_policy_conf']
for e in es:
 if e['segment'] not in ('__DATA_CONST','__DATA'):continue
 data=read(e['va'],e['size'])
 for name in strings:
  at=0
  while (at:=data.find(struct.pack('<Q',name),at))>=0:
   address=e['va']+at-fields['mpc_name'];at+=1
   if address%8:continue
   full=q(address+fields['mpc_fullname'])
   try:fullname=read(full,len(b'Seatbelt sandbox policy\0'))
   except ValueError:continue
   if fullname==b'Seatbelt sandbox policy\0':confs.append(address)
require(len(confs)==1,'Unique actual original Sandbox policy conf')
conf=confs[0];ops=q(conf+fields['mpc_ops']);hooks={}
for name,offset in layouts['mac_policy_ops'].items():
 address=q(ops+offset);require(text['va']<=address<text['va']+text['size'],'Actual original policy callback executable')
 hooks[name]=address
opened=hooks['mpo_iokit_check_open'];body=read(opened,256)
sequence=struct.pack('<4I',0xf9006fe1,0x910003e2,0x528007e1,struct.unpack('<I',read(opened+112,4))[0])
require(body[100:116]==sequence and n['branch'](opened+112)>=text['va'],'Actual client x1 -> filter context +216, operation 63 -> original evaluator')
def calls(name):
 target=n['names'][name];found=[]
 for at in range(0,len(code)-12,4):
  a,b,c=struct.unpack_from('<3I',code,at)
  if a&0x9f00001f==0x90000010 and b&0xffc003ff==0xf9400210 and c==0xd61f0200 and n['imported'](text['va']+at)==target:
   stub=text['va']+at
   for off in range(0,len(code),4):
    word=struct.unpack_from('<I',code,off)[0]
    if word&0xfc000000==0x94000000 and n['branch'](text['va']+off)==stub:found.append(text['va']+off)
 return found
super_calls=calls('__ZNK11OSMetaClass13getSuperClassEv');name_calls=calls('__ZNK11OSMetaClass12getClassNameEv')
walks=[]
for call in super_calls:
 if call-44 not in name_calls:continue
 start=call-128;words=struct.unpack('<44I',read(start,176))
 if words[:5]!=(0xa9bc5ff8,0xa90157f6,0xa9024ff4,0xa9037bfd,0x9100c3fd):continue
 require(words[15:18]==(0xf9400008,0xf9401d08,0xd63f0100),'Actual getMetaClass slot 7, no class-name substitution')
 require(words[33:35]==(0xaa0003f7,0xb5fffe40) and words[-1]==0xd65f03c0,'Actual superclass result feeds non-null backward class walk')
 # Decode the actual CBNZ target, independently of displayed disassembly.
 word=words[34];imm=(word>>5)&0x7ffff;dest=start+136+4*(imm-(1<<19) if imm&(1<<18) else imm)
 require(dest==call-48,'Superclass loop returns to real current-class name call')
 walks.append(dict(address=hex(start),bytes=176,sha256=hashlib.sha256(read(start,176)).hexdigest(),get_class_name_call=hex(call-44),get_super_class_call=hex(call),back_edge=hex(dest)))
require(len(walks)==1,'Unique actual exact/prefix class-filter walk with genuine superclass traversal')
report=dict(original_sandbox_text_sha256=digest,reference_candidate_sha256=n['plan']['candidate_sha256'],compiled_policy_layout_object_sha256=hashlib.sha256(obj.read_bytes()).hexdigest(),layouts=layouts,
 policy_conf=hex(conf),policy_ops=hex(ops),hooks={name:hex(a) for name,a in hooks.items()},client_filter_context_offset=216,open_policy_operation=63,class_walk=walks[0],
 source_analysis_only=True,system_app_authorization_qualified=False,system_metal=False,original_desktop=False,adreno_execution=False)
(ROOT/'build/gpu-analysis/original-sandbox-client-class.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: unchanged original Sandbox policy hook and real getMetaClass/getClassName/getSuperClass loop derived; actual signed-policy behavior requires runtime controls')
