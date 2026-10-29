#!/usr/bin/env python3
"""Derive the supplied target's real shared-event handle/port ABI, read-only."""
import hashlib,json,runpy,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
n=runpy.run_path(str(ROOT/'scripts/audit-target-metal-device.py'))
read,pointer,cls,symbol,require=n['read'],n['pointer'],n['cls'],n['symbol'],n['require']
handle=cls(symbol('_OBJC_CLASS_$_MTLSharedEventHandle'));listener=cls(symbol('_OBJC_CLASS_$_MTLSharedEventListener'))
require(handle['instance_size']==16 and handle['instance_start']==8 and cls(handle['superclass'])['name']=='NSObject','Actual original 16-byte handle and NSObject base')
methods={m['selector']:m for m in handle['methods']}
for name,encoding in {'eventPort':'I16@0:8','label':'@16@0:8','labelTraceID':'Q16@0:8','initWithSharedEvent:':'@24@0:8@16','encodeWithCoder:':'v24@0:8@16','initWithCoder:':'@24@0:8@16'}.items():require(methods[name]['encoding']==encoding,'Exact original handle selector ABI: '+name)
meta=cls(pointer(handle['address']));secure=next(m for m in meta['methods'] if m['selector']=='supportsSecureCoding')
require(secure['encoding']=='B16@0:8' and read(secure['implementation'],8)==struct.pack('<2I',0x52800020,0xd65f03c0),'Original secure coding implementation genuinely returns true')
for name,second in [('eventPort',0xb9400100),('label',0xf9400500),('labelTraceID',0xf9400900)]:require(read(methods[name]['implementation'],12)==struct.pack('<3I',0xf9400408,second,0xd65f03c0),'Actual 24-byte private-data getter: '+name)
constructor=methods['initWithSharedEvent:']['implementation'];code=read(constructor,204)
require(struct.unpack_from('<2I',code,0x38)==(0x52800300,0x52800021),'Actual constructor allocates 24 bytes of zeroed private data')
def adrp(pc,word):
 value=((word>>5)&0x7ffff)*4+((word>>29)&3)
 if value&(1<<20):value-=1<<21
 return (pc&~4095)+(value<<12)
def branch(pc):
 word=struct.unpack('<I',read(pc,4))[0];require(word&0xfc000000==0x94000000,'Actual linked branch')
 value=word&0x3ffffff;return pc+4*(value-(1<<26) if value&(1<<25) else value)
calls=[]
for offset in range(0,len(code),4):
 word=struct.unpack_from('<I',code,offset)[0]
 if word&0xfc000000!=0x94000000:continue
 target=branch(constructor+offset);a,b,c,d,e=struct.unpack('<5I',read(target,20))
 if a&0x9f00001f==0x90000001 and b&0xffc003ff==0xf9400021 and c&0x9f00001f==0x90000010 and d&0xffc003ff==0xf9400210 and e==0xd61f0200:
  name=n['string'](pointer(adrp(target,a)+((b>>10)&4095)*8));calls.append(dict(call=constructor+offset,stub=target,selector=name))
require([r['selector'] for r in calls]==['eventPort','label','copy','labelTraceID'],'Original constructor borrows the real port, copies the label and reads its typed trace getter')
require(struct.unpack_from('<2I',code,0x70)==(0x52800002,0x52800023),'Actual send-right kind zero and reference increment one')
stub=branch(constructor+0x78);a,b,c=struct.unpack('<3I',read(stub,12));require(a&0x9f00001f==0x90000010 and b&0xffc003ff==0x91000210 and c==0xd61f0200,'Original optimized direct import stub')
ref_function=adrp(stub,a)+((b>>10)&4095)
# Prove the imported public function through the original libsystem export trie.
main=n['main'];at,count=struct.unpack_from('<2Q',main,136);image_va=None
for i in range(count):
 uuid,va,_,name=struct.unpack_from('<16sQ2I',main,at+32*i)
 if main[name:main.find(b'\0',name)]==b'/usr/lib/system/libsystem_kernel.dylib':image_va=va;break
require(image_va is not None,'Original libsystem kernel image')
header=read(image_va,32);blob=header+read(image_va+32,struct.unpack_from('<I',header,20)[0]);image=n['n']['macho'](blob);link=next(s for s in image['segments'] if s['name']=='__LINKEDIT');export=None
for cmd,pos,_ in image['commands']:
 if cmd==0x80000033:export=struct.unpack_from('<2I',blob,pos+8)
 elif cmd==0x80000022:
  candidate=struct.unpack_from('<2I',blob,pos+40)
  if candidate[1]:export=candidate
require(export is not None and link['fileoff']<=export[0] and export[0]+export[1]<=link['fileoff']+link['filesize'],'Original LINKEDIT-backed kernel export trie')
tree=read(link['va']+export[0]-link['fileoff'],export[1]);pending=[(0,'')];visited=set();functions={};uleb=n['n']['uleb']
while pending:
 at,prefix=pending.pop();require(at not in visited and len(visited)<100000,'Bounded original trie');visited.add(at);length,start=uleb(tree,at);require(start+length<len(tree),'Bounded original export extent')
 if length:
  flags,cursor=uleb(tree,start)
  if not flags&8:
   value,_=uleb(tree,cursor);functions[prefix]=value if flags&3==2 else image_va+value
 at=start+length;children=tree[at];at+=1
 for _ in range(children):
  end=tree.index(0,at);label=tree[at:end].decode('ascii');child,at=uleb(tree,end+1);pending.append((child,prefix+label))
require(functions['_mach_port_mod_refs']==ref_function,'Actual constructor retains a real Mach send right through original mach_port_mod_refs')
require({m['selector']:m['encoding'] for m in listener['methods']}=={'init':'@16@0:8','initWithDispatchQueue:':'@24@0:8@16'},'Actual original listener construction ABI, no later-OS API substitution')
concrete=cls(symbol('_OBJC_CLASS_$_MTLSharedEventListenerInternal'));get_queue=next(m for m in concrete['methods'] if m['selector']=='dispatchQueue')
require(concrete['instance_size']==24 and concrete['superclass']==listener['address'] and get_queue['encoding']=='@16@0:8','Actual original concrete listener and typed dispatch queue accessor')
qa,qb,qc,qd=struct.unpack('<4I',read(get_queue['implementation'],16))
require(qa&0x9f00001f==0x90000008 and qb&0xffc003ff==0xb9800108 and qc==0xf8686800 and qd==0xd65f03c0,'Original dispatch queue getter uses its genuine loaded ivar offset')
queue_ivar_address=adrp(get_queue['implementation'],qa)+((qb>>10)&4095)*4
queue_ivar_offset=struct.unpack('<i',read(queue_ivar_address,4))[0]
require(queue_ivar_offset in (8,16),'Original dispatch queue ivar is within the actual concrete listener')

coding_methods={}
for name,length,class_offset in [('encodeWithCoder:',164,24),('initWithCoder:',220,44)]:
 start=methods[name]['implementation'];raw=read(start,length);ca,cb=struct.unpack_from('<2I',raw,class_offset)
 require(ca&0x9f00001f==0x90000008 and cb&0xffc003ff==0xf9400100,'Actual original coder class reference load')
 reference=adrp(start+class_offset,ca)+((cb>>10)&4095)*8;coder=cls(pointer(reference))
 require(coder['name']=='NSXPCCoder','Original handle explicitly requires the real NSXPCCoder class')
 selectors=[]
 for offset in range(0,length,4):
  word=struct.unpack_from('<I',raw,offset)[0]
  if word&0xfc000000 not in (0x94000000,0x14000000):continue
  delta=word&0x3ffffff;target=start+offset+4*(delta-(1<<26) if delta&(1<<25) else delta)
  a,b,c,d,e=struct.unpack('<5I',read(target,20))
  if a&0x9f00001f==0x90000001 and b&0xffc003ff==0xf9400021 and c&0x9f00001f==0x90000010 and d&0xffc003ff==0xf9400210 and e==0xd61f0200:
   selectors.append(n['string'](pointer(adrp(target,a)+((b>>10)&4095)*8)))
 expected=['raise:format:','encodeXPCObject:forKey:','encodeObject:forKey:'] if name=='encodeWithCoder:' else ['raise:format:','decodeXPCObjectOfType:forKey:','decodeObjectOfClass:forKey:']
 require(selectors==expected,'Original NSXPC-only object/port coding selectors: '+name+' '+repr(selectors))
 coding_methods[name]=dict(implementation=start,bytes=length,sha256=hashlib.sha256(raw).hexdigest(),required_coder_class=coder['name'],selectors=selectors)
report=dict(coding_methods=coding_methods,cache_uuid=main[88:104].hex(),handle=handle,listener=listener,concrete_listener=concrete,listener_queue_ivar_offset=queue_ivar_offset,private_bytes=24,constructor_sha256=hashlib.sha256(code).hexdigest(),constructor_calls=calls,mach_port_mod_refs=hex(ref_function),actual_send_ref_increment=1,metadata_only=True,native_mach_export_qualified=False,original_desktop=False,adreno_execution=False)
(ROOT/'build/gpu-analysis/shared-event-handle-contract.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: exact original secure handle, typed port/label/trace ABI and real Mach send-right retain; native export/import remains unqualified')
