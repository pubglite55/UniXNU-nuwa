#!/usr/bin/env python3
"""Derive exact original Metal device ABI metadata without extracting executable code."""
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess
ROOT=Path(__file__).resolve().parents[1]
n=runpy.run_path(str(ROOT/'scripts/audit-target-metal-discovery.py'))
read,pointer,symbol,require=n['read'],n['pointer'],n['symbol'],n['require']
OUT=ROOT/'build/gpu-analysis';main=n['main'];region=n['region']
source=OUT/'metal-device-layout.cpp';exe=OUT/'metal-device-layout'
source.write_text('#include <cstddef>\n#include <cstdio>\n#include "dyld_cache_format.h"\nint main(){printf("%zu\\n",offsetof(dyld_cache_header,objcOptsOffset));}\n')
subprocess.run(['xcrun','clang++','-I',ROOT/'refer/dyld/cache-builder',source,'-o',exe],check=True,timeout=30)
require(subprocess.check_output([exe],text=True).strip()=='464','Compiler-derived ObjC optimization-header field')
opt=region+struct.unpack_from('<Q',main,464)[0]
require(struct.unpack('<I',read(opt,4))[0]==1,'Actual supported ObjC optimization header version')
selector_base=region+struct.unpack('<Q',read(opt+48,8))[0]
def string(address):
    out=bytearray()
    # Bound reads also at file-mapping boundaries instead of speculative 4K reads.
    for i in range(4096):
        b=read(address+i,1)
        if b==b'\0':return out.decode('utf-8')
        out+=b
    raise SystemExit('Unterminated original ObjC metadata string')
def methods(address):
    if not address:return []
    if address&1:
        header=address&~1;stride,count=struct.unpack('<II',read(header,8))
        require(stride==8 and 0<count<=4096,f'Bounded cache category list-of-lists {header:x} stride={stride} count={count}')
        entry=header+count*8
        offset=struct.unpack('<q',read(entry,8))[0]>>16
        address=entry+offset  # Pinned MachOAnalyzer: final list is the class list.
    flags,count=struct.unpack('<II',read(address,8));size=flags&0xfffc
    require(count<=4096 and size==(12 if flags&0x80000000 else 24),f'Bounded actual method list profile {address:x} flags={flags:x} count={count}')
    result=[]
    for i in range(count):
        entry=address+8+i*size
        if flags&0x80000000:
            nameoff,typeoff,impoff=struct.unpack('<Iii',read(entry,12))
            if flags&0x40000000:name=selector_base+nameoff
            else:name=pointer(entry+struct.unpack('<i',read(entry,4))[0])
            types=entry+4+typeoff;imp=entry+8+impoff
        else:name,types,imp=(pointer(entry+j) for j in (0,8,16))
        selector=string(name);encoding=string(types)
        require(selector and encoding and imp%4==0,'Original method selector/types/aligned implementation')
        result.append(dict(selector=selector,encoding=encoding,implementation=imp))
    require(len({x['selector'] for x in result})==len(result),'Unique original own method selectors')
    return sorted(result,key=lambda x:x['selector'])
def cls(address):
    ro=pointer(address+32)&0x00007ffffffffff8
    flags,start,size=struct.unpack('<III',read(ro,12));name=string(pointer(ro+24))
    require(size>=start and size<=1024*1024 and name,'Bounded actual class instance layout')
    return dict(address=address,name=name,superclass=pointer(address+8),instance_start=start,instance_size=size,
                methods=methods(pointer(ro+32)))
base=cls(symbol('_OBJC_CLASS_$__MTLDevice'));meta=cls(pointer(base['address']))
require(base['name']=='_MTLDevice' and base['instance_size']==536 and len(base['methods'])==575,'Exact original base-device metadata')
# Record actual ancestry; the bundle principal's name alone does not establish
# which runtime device class will be published. Never inherit an AGX class.
family=[];address=symbol('_OBJC_CLASS_$_AGXA10FamilyDevice')
while address:
    require(len(family)<16 and address not in {x['address'] for x in family},'Bounded original class ancestry')
    item=cls(address);family.append(item);address=item['superclass']
require(any(x['name']=='_MTLDevice' for x in family),'Actual Apple device ancestry reaches Metal base')
principal=cls(symbol('_OBJC_CLASS_$_AGXPrincipalDevice'))
require(cls(principal['superclass'])['name']=='NSObject','Original principal class has NSObject ancestry')
functions={name:symbol(name) for name in ('_MTLCreateSystemDefaultDevice','_MTLRegisterDevices')}
pins={str(p.relative_to(ROOT/'refer/dyld')):hashlib.sha256(p.read_bytes()).hexdigest() for p in
      (ROOT/'refer/dyld/common/ObjCVisitor.h',ROOT/'refer/dyld/common/ObjCVisitor.cpp',ROOT/'refer/dyld/common/DyldSharedCache.h',ROOT/'refer/dyld/common/DyldSharedCache.cpp',ROOT/'refer/dyld/common/MachOAnalyzer.cpp',ROOT/'refer/dyld/common/OptimizerObjC.h')}
report=dict(cache_uuid=main[88:104].hex(),dyld_revision=subprocess.check_output(['git','-C',ROOT/'refer/dyld','rev-parse','HEAD'],text=True).strip(),
    layout_source_sha256=pins,selector_base=selector_base,device=base,metaclass=meta,
    principal_class={k:v for k,v in principal.items() if k!='methods'},
    apple_device_ancestry=[{k:v for k,v in x.items() if k!='methods'} for x in family],functions=functions,
    runtime_observed=False,native_adreno_device=False)
(OUT/'metal-device-abi.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: original _MTLDevice has',len(base['methods']),'own methods,',len(meta['methods']),'class methods and',base['instance_size'],'instance bytes')
print('Actual Apple family ancestry:', ' -> '.join(c['name'] for c in family))
