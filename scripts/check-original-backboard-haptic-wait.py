#!/usr/bin/env python3
import sys,struct,json,argparse,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
a=argparse.ArgumentParser(description="Inspect original backboardd's haptic group wait; static analysis only")
a.add_argument('--backboardd',type=Path,required=True);a.add_argument('--report',type=Path,required=True);args=a.parse_args()
sys.path.insert(0,str(ROOT/'kits/XnuPrelink'));from native_prelink import macho,backed_offset
raw=args.backboardd.read_bytes();sha=hashlib.sha256(raw).hexdigest()
assert sha=='6e362a46a2b46eb2741ecc6fcb50ffecb2fbc299641159045475361e62b34634'
m=macho(raw)
def rd(va,n):return raw[backed_offset(m['segments'],va,n,len(raw)):][:n]
def u32(va):return struct.unpack('<I',rd(va,4))[0]
def i32(va):return struct.unpack('<i',rd(va,4))[0]
def ptr(va):
 v=struct.unpack('<Q',rd(va,8))[0]
 if not v or v>>63:return 0
 v &= (1<<36)-1
 return v if v>=0x100000000 else 0x100000000+v
def cs(va):return rd(va,256).split(b'\0')[0].decode(errors='replace')
sections={};at=32
for i in range(struct.unpack_from('<I',raw,16)[0]):
 cmd,n=struct.unpack_from('<II',raw,at)
 if cmd==0x19:
  count=struct.unpack_from('<I',raw,at+64)[0]
  for j in range(count):
   a=at+72+j*80;name=raw[a:a+16].split(b'\0')[0].decode();va,size=struct.unpack_from('<QQ',raw,a+32);sections[name]=(va,size)
 at+=n
out=[]
def methods(cls,meta=False):
 ro=ptr(cls+32)&~7
 if not ro:return
 name=cs(ptr(ro+24));lst=ptr(ro+32)
 if not lst:return
 flags,count=struct.unpack('<II',rd(lst,8));size=flags&0xffff
 assert count<10000 and size in [12,24],(name,hex(flags),count)
 for j in range(count):
  e=lst+8+j*size
  if flags&0x80000000:
   np=e+i32(e);sel=cs(np if flags&0x40000000 else ptr(np));imp=e+8+i32(e+8)
  else:sel=cs(ptr(e));imp=ptr(e+16)
  out.append((imp,('+' if meta else '-')+'['+name+' '+sel+']'))
va,size=sections['__objc_classlist']
for a in range(va,va+size,8):
 cls=ptr(a);methods(cls);meta=ptr(cls)
 if meta:methods(meta,True)
out.sort();methods=dict(out)
assert methods[0x10002fe4c]=='-[BKButtonHapticsController applyDefinitions:]'
# Relative block invoke reference in this exact method, then an infinite group wait.
def branch(pc,link=True):
 word=u32(pc);assert word>>26==(0b100101 if link else 0b000101)
 n=word&0x3ffffff;n-=1<<26 if n&(1<<25) else 0
 return pc+n*4
def adr(pc):
 word=u32(pc);assert word&0x9f000000==0x10000000
 n=((word>>5)&0x7ffff)<<2|((word>>29)&3);n-=1<<21 if n&(1<<20) else 0
 return pc+n
assert adr(0x10002fef4)==0x1000303c4
assert u32(0x1000303dc)==0x92800001 # mov x1,-1, DISPATCH_TIME_FOREVER
assert branch(0x1000303e0)==0x10009765c
assert branch(0x1000303f0,False)==0x100099d00
assert cs(ptr(0x100103de8))=='_queue_applyDefinitions:'
assert branch(0x100023284)==0x100096d68 # original main run-loop call
report=dict(passed=True,backboardd_sha256=sha,analysis='static-original-ARM64',
 method=methods[0x10002fe4c],method_start=hex(0x10002fe4c),block=hex(0x1000303c4),
 group_wait_return=hex(0x1000303e4),timeout='DISPATCH_TIME_FOREVER',
 following_selector=cs(ptr(0x100103de8)),main_runloop_return=hex(0x100023288),
 UI_blocking_dependency_proven=False,hardware_executed=False)
args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2)+'\n')
print('PASS: original applyDefinitions block waits forever for the haptic controller group; no claim that this causes the UI stall')
