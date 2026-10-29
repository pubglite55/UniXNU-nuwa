#!/usr/bin/env python3
"""Read exact original Foundation/libxpc endpoint ABI without extracting images."""
import hashlib,json,runpy,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
n=runpy.run_path(str(ROOT/'scripts/audit-target-metal-device.py'))
read,require=n['read'],n['require'];main=n['main'];at,count=struct.unpack_from('<2Q',main,136)
wanted={'/System/Library/Frameworks/Foundation.framework/Foundation','/usr/lib/system/libxpc.dylib'};images={};exports={}
for i in range(count):
 uuid,va,_,name=struct.unpack_from('<16sQ2I',main,at+32*i);end=main.find(b'\0',name);require(end>=name,'Bounded original image name');path=main[name:end].decode()
 if path not in wanted:continue
 header=read(va,32);blob=header+read(va+32,struct.unpack_from('<I',header,20)[0]);image=n['n']['macho'](blob)
 actual_uuid=next(blob[p+8:p+24] for cmd,p,_ in image['commands'] if cmd==0x1b);require(actual_uuid==uuid,'Original image/cache UUID identity')
 link=next(s for s in image['segments'] if s['name']=='__LINKEDIT');entry=None
 for cmd,pos,_ in image['commands']:
  if cmd==0x80000033:entry=struct.unpack_from('<2I',blob,pos+8)
  elif cmd==0x80000022:
   candidate=struct.unpack_from('<2I',blob,pos+40)
   if candidate[1]:entry=candidate
 require(entry and link['fileoff']<=entry[0] and entry[0]+entry[1]<=link['fileoff']+link['filesize'],'Original LINKEDIT-backed export trie')
 tree=read(link['va']+entry[0]-link['fileoff'],entry[1]);pending=[(0,'')];visited=set();items={};uleb=n['n']['uleb']
 while pending:
  pos,prefix=pending.pop();require(pos not in visited and len(visited)<100000,'Bounded original export trie');visited.add(pos);length,start=uleb(tree,pos);require(start+length<len(tree),'Bounded terminal record')
  if length:
   flags,cursor=uleb(tree,start)
   if not flags&8:
    value,_=uleb(tree,cursor);items[prefix]=value if flags&3==2 else va+value
  pos=start+length;children=tree[pos];pos+=1
  for _ in range(children):
   end=tree.index(0,pos);label=tree[pos:end].decode('ascii');child,pos=uleb(tree,end+1);pending.append((child,prefix+label))
 images[path]=dict(va=va,uuid=uuid.hex(),export_trie_sha256=hashlib.sha256(tree).hexdigest());exports[path]=items
require(set(images)==wanted,'Exact original Foundation and libxpc images')
foundation=exports['/System/Library/Frameworks/Foundation.framework/Foundation'];libxpc=exports['/usr/lib/system/libxpc.dylib'];classes={}
for name in ('NSXPCListenerEndpoint','NSXPCCoder'):
 symbol='_OBJC_CLASS_$_'+name;require(symbol in foundation,'Actual original exported class '+name);classes[name]=n['cls'](foundation[symbol])
functions={name:address for name,address in libxpc.items() if name.startswith('_xpc_') and ('endpoint' in name or 'pipe_' in name or 'mach_send' in name)}
endpoint=classes['NSXPCListenerEndpoint'];methods={m['selector']:m for m in endpoint['methods']}
require(endpoint['instance_size']==20 and n['cls'](endpoint['superclass'])['name']=='NSObject','Original endpoint layout and ancestry')
for name,encoding in {'_endpoint':'@16@0:8','_setEndpoint:':'v24@0:8@16','init':'@16@0:8','_initWithConnection:':'@24@0:8@16'}.items():require(methods[name]['encoding']==encoding,'Actual endpoint method ABI '+name)
# The target receive entry saves/forwards a THIRD register argument. Older
# external two-argument declarations do not qualify this supplied target ABI.
create=read(functions['_xpc_pipe_create_from_port'],16);send=read(functions['_xpc_pipe_simpleroutine'],20);receive=read(functions['_xpc_pipe_receive'],204)
require(struct.unpack_from('<3I',create)==(0xaa0103e2,0xaa0003e1,0xd2800000),'Actual port/flags forwarding in original pipe creation')
require(struct.unpack_from('<4I',send)==(0xaa0103e2,0x52800001,0x52800003,0xd2800004),'Actual original simpleroutine request and zero reply arguments')
require(struct.unpack_from('<3I',receive,20)==(0xaa0203f4,0xaa0103f3,0xaa0003f5),'Actual receive preserves flags/output/port register arguments')
windows={name:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) for name,raw in [('create_from_port',create),('simpleroutine',send),('receive',receive)]}
report=dict(cache_uuid=main[88:104].hex(),images=images,classes=classes,functions=functions,entry_windows=windows,receive_third_argument_observed=True,metadata_only=True,cross_process_nsxpc_qualified=False,original_desktop=False,adreno_execution=False)
(ROOT/'build/gpu-analysis/original-xpc-endpoints.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(classes['NSXPCListenerEndpoint'],indent=2));print(json.dumps({name:hex(va) for name,va in functions.items()},indent=2))
print('PASS: exact original endpoint class metadata and libxpc exported entry addresses; no cross-process NSXPC execution claimed')
