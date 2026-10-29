#!/usr/bin/env python3
"""Read the exact original RenderBox class/export ABI; no runtime qualification."""
import hashlib
import json
from pathlib import Path
import runpy
import struct
ROOT=Path(__file__).resolve().parents[1]
n=runpy.run_path(str(ROOT/'scripts/audit-target-metal-device.py'))
read,cls,main,require=n['read'],n['cls'],n['main'],n['require']
a=n['n'];macho,uleb=a['macho'],a['uleb']
at,count=struct.unpack_from('<2Q',main,136);matches=[]
for i in range(count):
    uuid,va,_,path=struct.unpack_from('<16sQ2I',main,at+i*32)
    name=main[path:main.find(b'\0',path)].decode()
    if name.endswith('/RenderBox.framework/RenderBox'):matches.append((uuid,va,name))
require(len(matches)==1,'One original RenderBox image')
uuid,va,name=matches[0];size=struct.unpack('<I',read(va+20,4))[0];blob=read(va,32+size);image=macho(blob)
require(next(blob[p+8:p+24] for c,p,_ in image['commands'] if c==0x1b)==uuid,'Exact original RenderBox Mach-O/cache UUID')
link=next(s for s in image['segments'] if s['name']=='__LINKEDIT');export=None
for c,p,_ in image['commands']:
    if c==0x80000033:export=struct.unpack_from('<2I',blob,p+8)
    elif c==0x80000022:
        candidate=struct.unpack_from('<2I',blob,p+40)
        if candidate[1]:export=candidate
require(export and link['fileoff']<=export[0] and export[0]+export[1]<=link['fileoff']+link['filesize'],'Original export trie extent')
tree=read(link['va']+export[0]-link['fileoff'],export[1]);pending=[(0,'')];visited=set();symbols={}
while pending:
    at,prefix=pending.pop();require(at not in visited and len(visited)<100000,'Bounded original trie');visited.add(at)
    terminal,start=uleb(tree,at);require(start+terminal<len(tree),'Bounded terminal')
    if terminal:
        flags,cursor=uleb(tree,start)
        if not flags&8:
            value,_=uleb(tree,cursor);symbols[prefix]=value if flags&3==2 else va+value
    at=start+terminal;children=tree[at];at+=1
    for _ in range(children):
        end=tree.index(0,at);label=tree[at:end].decode();child,at=uleb(tree,end+1);pending.append((child,prefix+label))
device=cls(symbols['_OBJC_CLASS_$_RBDevice']);methods={m['selector']:m for m in device['methods']}
for selector,encoding in {'initWithDevice:':'@24@0:8@16','device':'@16@0:8','queue':'@16@0:8',
        'renderImageInRect:options:renderer:':'^{CGImage=}64@0:8{CGRect={CGPoint=dd}{CGSize=dd}}16@48@?56'}.items():
    require(methods[selector]['encoding']==encoding,'Actual original method ABI: '+selector)
family=next(m for m in n['base']['methods'] if m['selector']=='supportsFamily:')
require(family['encoding']=='B24@0:8q16','Actual original family-query ABI')
queue=cls(a['symbol']('_OBJC_CLASS_$_MTLIOAccelCommandQueue'))
priorities=[m for m in queue['methods'] if m['selector'] in ('getGPUPriority','getBackgroundGPUPriority','setGPUPriority:','setBackgroundGPUPriority:')]
require(len(priorities)==4 and all(m['encoding']==('B24@0:8Q16' if m['selector'].startswith('set') else 'Q16@0:8') for m in priorities),
    'Actual original foreground/background queue-priority method ABIs')
command=cls(a['symbol']('_OBJC_CLASS_$__MTLCommandBuffer'));command_methods={m['selector']:m for m in command['methods']}
command_abi={'enqueue':'v16@0:8','commitAndWaitUntilSubmitted':'B16@0:8','addCompletedHandler:':'v24@0:8@?16','addScheduledHandler:':'v24@0:8@?16'}
require(all(command_methods[s]['encoding']==encoding for s,encoding in command_abi.items()),'Actual original command enqueue/submission/callback ABIs')
library_methods=[m for m in n['base']['methods'] if m['selector'] in ('newPipelineLibraryWithFilePath:error:','newLibraryWithFile:error:','newLibraryWithURL:error:')]
require(len(library_methods)==3 and all(m['encoding']=='@32@0:8@16^@24' for m in library_methods),'Actual original pipeline-archive and library-file/URL method ABIs')
out=ROOT/'build/gpu-analysis/renderbox-device-abi.json'
out.write_text(json.dumps(dict(cache_uuid=main[88:104].hex(),image_uuid=uuid.hex(),image=name,device=device,
    original_queue_priority_methods=priorities,
    original_command_methods=[command_methods[s] for s in command_abi],
    original_device_library_methods=library_methods,
    original_base_family_method=family,original_base_family_entry_sha256=hashlib.sha256(read(family['implementation'],60)).hexdigest(),
    metadata_only=True,runtime_observed=False,original_desktop=False),indent=2)+'\n')
print('PASS: exact original RenderBox export/class/init/device/queue/render ABI; runtime success is checked independently')
