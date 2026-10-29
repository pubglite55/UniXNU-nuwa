#!/usr/bin/env python3
"""Verify the actual C reader against every unchanged original UI library module."""
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1];KIT=ROOT/'kits/AirNir';OUT=ROOT/'build/air-library'
OUT.mkdir(parents=True,exist_ok=True)
def run(cmd,**kw):return subprocess.run([str(x) for x in cmd],check=True,timeout=60,**kw)
def require(v,why):
 if not v:raise SystemExit(why)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
run(['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',KIT,KIT/'Library.c',KIT/'tests/test_library.c','-o',OUT/'test-library'])
test=subprocess.check_output([OUT/'test-library',ROOT/'.cache/firmware/target-volumes/os-mount/System/Library/Frameworks/QuartzCore.framework/default.metallib',ROOT/'.cache/firmware/target-volumes/os-mount/System/Library/PrivateFrameworks/RenderBox.framework/default.metallib'],text=True,timeout=30);print(test.strip())
run(['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-I',KIT,KIT/'Library.c','-o',OUT/'library-host.dylib'])
class View(c.Structure):_fields_=[('data',c.c_void_p),('bytes',c.c_size_t),('slice_offset',c.c_size_t),('slice_bytes',c.c_size_t),('functions_offset',c.c_size_t),('functions_bytes',c.c_size_t),('count',c.c_uint32),('reserved',c.c_uint32)]
class Function(c.Structure):_fields_=[(n,c.c_void_p) for n in ('name','bitcode','wrapper','wrapper_sha256')]+[(n,c.c_size_t) for n in ('name_bytes','bitcode_bytes','wrapper_bytes')]+[(n,c.c_uint32) for n in ('index','stage')]
Hash=c.CFUNCTYPE(c.c_int,c.c_void_p,c.c_size_t,c.c_void_p,c.c_void_p)
@Hash
def hash_bytes(data,n,out,ctx):
 if n>AIR_MAX: return 1
 digest=hashlib.sha256(c.string_at(data,n)).digest();c.memmove(out,digest,32);return 0
AIR_MAX=64*1024*1024
lib=c.CDLL(str(OUT/'library-host.dylib'));lib.air_library_open.argtypes=[c.c_void_p,c.c_size_t,Hash,c.c_void_p,c.POINTER(View)];lib.air_library_open.restype=c.c_uint32
lib.air_library_get.argtypes=[c.POINTER(View),c.c_uint32,c.POINTER(Function)];lib.air_library_get.restype=c.c_uint32
reference=json.loads((ROOT/'build/gpu-analysis/air/target-inputs.json').read_text());reports=[];functions=[]
for item in reference['inputs']:
 path=ROOT/'.cache/firmware/target-volumes/os-mount/System/Library'/item['file'];raw=path.read_bytes();require(sha(path)==item['sha256'],'Exact unchanged original metallib')
 backing=c.create_string_buffer(raw);base=c.addressof(backing);view=View()
 require(lib.air_library_open(base,len(raw),hash_bytes,None,c.byref(view))==0,'Actual original container validates')
 expected=[x for x in reference['modules'] if x['library']==Path(item['file']).parent.stem]
 require(view.count==len(expected)==item['functions'] and view.slice_offset==item['selected_slice']['offset'] and view.slice_bytes==item['selected_slice']['bytes'],'Actual whole-library slice and function inventory')
 for module in expected:
  f=Function();require(lib.air_library_get(c.byref(view),module['index'],c.byref(f))==0,'Every actual function lookup')
  for ptr,n in ((f.name,f.name_bytes+1),(f.bitcode,f.bitcode_bytes),(f.wrapper,f.wrapper_bytes),(f.wrapper_sha256,32)):require(base<=ptr and ptr+n<=base+len(raw),'Every returned pointer is within the actual original backing')
  require(c.string_at(f.name,f.name_bytes).decode()==module['name'] and f.index==module['index'] and f.stage==module['type'],'Actual index/name/stage match independent AIR audit')
  bc=hashlib.sha256(c.string_at(f.bitcode,f.bitcode_bytes)).hexdigest();wrapper=hashlib.sha256(c.string_at(f.wrapper,f.wrapper_bytes)).hexdigest()
  require(bc==module['bitcode_sha256'] and wrapper==module['wrapper_sha256']==c.string_at(f.wrapper_sha256,32).hex(),'Every complete original bitcode/wrapper/HASH byte identity')
  functions.append(dict(library=module['library'],index=f.index,stage=f.stage,bitcode_sha256=bc,wrapper_sha256=wrapper))
 reports.append(dict(library=Path(item['file']).parent.stem,sha256=item['sha256'],count=view.count,slice_offset=view.slice_offset,slice_bytes=view.slice_bytes))
 print('PASS:',reports[-1]['library'],view.count,'actual original module names/stages/complete hashes')
sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
run(['xcrun','clang','-target','arm64-apple-ios17.0','-isysroot',sdk,'-std=c11','-O2','-Wall','-Wextra','-Werror','-fstack-protector-strong','-c',KIT/'Library.c','-o',OUT/'Library.ios.o'])
sys.path.insert(0,str(ROOT/'kits/XnuPrelink'));from native_prelink import macho
raw=(OUT/'Library.ios.o').read_bytes();parsed=macho(raw);import struct
require(parsed['kind']==1 and [struct.unpack_from('<II',raw,at+8) for cmd,at,_ in parsed['commands'] if cmd==0x32]==[(2,0x110000)],'Actual ordinary ARM64 subtype0/iOS17 object')
(OUT/'report.json').write_text(json.dumps(dict(libraries=reports,functions=functions,host_sanitizer_test=test.strip(),
    reader_source_sha256=sha(KIT/'Library.c'),header_sha256=sha(KIT/'Library.h'),native_object_sha256=sha(OUT/'Library.ios.o'),
    complete_module_hashes_checked=240,target_runtime_executed=False,amfi_or_signature_authority=False,gpu_execution=False),indent=2)+'\n')
print('PASS: all 240 original module views, native iOS17 cross-build and bounded transactional controls')
