#!/usr/bin/env python3
"""Run original launchd override loader and job gate with explicit OS API stand-ins."""
import argparse,hashlib,json,plistlib,struct,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--launchd',type=Path,required=True);p.add_argument('--policy',type=Path,required=True);p.add_argument('--python-modules',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
sys.path[:0]=[str(a.python_modules),str(root/'kits/XnuPrelink')]
from native_prelink import macho,backed_offset
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as regs
raw=a.launchd.read_bytes();sha=hashlib.sha256(raw).hexdigest();assert sha=='8cec9a3c44a443b08e977ccc5d577850316ad428c575dc01f09b018dbd5b6a25'
m=macho(raw);data=a.policy.read_bytes();assert plistlib.loads(data)=={'com.apple.watchdogd':True}
def w(pc):return struct.unpack_from('<I',raw,backed_offset(m['segments'],pc,4,len(raw)))[0]
results=[]
for label,uid,disabled in [('com.apple.watchdogd',0,True),('com.apple.watchdogd',502,False),('com.apple.other',0,False)]:
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 for s in m['segments']:
  if s['name']=='__PAGEZERO' or not s['size']:continue
  u.mem_map(s['va'],(s['size']+4095)&~4095);u.mem_write(s['va'],raw[s['fileoff']:s['fileoff']+s['filesize']])
 u.mem_map(0x200000000,0x40000)
 def setr(n,v):u.reg_write(getattr(regs,'UC_ARM64_REG_'+n.upper()),v)
 def getr(n):return u.reg_read(getattr(regs,'UC_ARM64_REG_'+n.upper()))
 def putq(addr,v):u.mem_write(addr,struct.pack('<Q',v))
 def cstr(addr):
  out=bytearray()
  for i in range(512):
   b=bytes(u.mem_read(addr+i,1))
   if b==b'\0':return out.decode()
   out+=b
  raise AssertionError('String bound')
 def bind_literal(pc,value):
  word=w(pc);assert word&0xff000000==0x58000000
  imm=(word>>5)&0x7ffff;imm-=0x80000 if imm&0x40000 else 0
  putq(pc+imm*4,value)
 DICT=0x200000010;BOOL=0x200000020;TRUE=0x200000030;OBJ=0x200000040;EMPTY=0x200000050
 # Resolve original imported data symbols; retain all original instructions.
 bind_literal(0x100046fb8,0x200000060)
 bind_literal(0x10003b1a0,DICT);bind_literal(0x10002dd6c,DICT);bind_literal(0x10002dd9c,BOOL);bind_literal(0x100004150,TRUE)
 encoded=struct.unpack_from('<Q',raw,backed_offset(m['segments'],0x100075970,8,len(raw)))[0]
 base=0x100000000+(encoded&0xfffffffff);assert cstr(base)=='/private/var/db/com.apple.xpc.launchd';putq(0x100075970,base)
 events=[];objects={OBJ:None,EMPTY:{}}
 def hook(uc,pc,size,_):
  def ret(v=0):setr('x0',v);setr('pc',getr('lr'))
  if pc==0x1000541ec:u.mem_write(getr('x0'),bytes([getr('x1')&255])*getr('x2'));ret(getr('x0'))
  elif pc==0x1000548a0:
   fmt=cstr(getr('x2'));assert fmt=='%s/disabled.migrated';s=(fmt%cstr(struct.unpack('<Q',bytes(u.mem_read(getr('sp'),8)))[0])).encode()+b'\0';u.mem_write(getr('x0'),s);ret(len(s)-1)
  elif pc==0x1000548b8:assert cstr(getr('x0'))==base_path+'/disabled.migrated';events.append('existing migration marker');ret()
  elif pc==0x100014644:
   fmt=cstr(getr('x0'));assert fmt=='%s/disabled.plist';s=(fmt%cstr(struct.unpack('<Q',bytes(u.mem_read(getr('sp'),8)))[0])).encode()+b'\0';u.mem_write(0x200001000,s);ret(0x200001000)
  elif pc==0x1000542d0:events.append(cstr(getr('x0')));assert events[-1]==base_path+'/disabled.plist';ret(7)
  elif pc==0x100053e20:
   st=bytearray(144);struct.pack_into('<H',st,4,0o100644);struct.pack_into('<I',st,16,uid);struct.pack_into('<Q',st,96,len(data));u.mem_write(getr('x1'),bytes(st));ret()
  elif pc==0x100012478:assert getr('x0')==len(data);ret(0x200002000)
  elif pc==0x1000547b0:assert getr('x0')==7 and getr('x2')==len(data);u.mem_write(getr('x1'),data);ret(len(data))
  elif pc==0x100054cb4:objects[OBJ]=plistlib.loads(bytes(u.mem_read(getr('x0'),getr('x1'))));ret(OBJ)
  elif pc==0x100054eac:ret(BOOL if getr('x0')==TRUE else DICT)
  elif pc==0x100054d38:ret(EMPTY)
  elif pc in (0x100053e08,0x100053a6c):ret()
  elif pc==0x100054dec:
   obj=objects[getr('x0')];key=cstr(getr('x1'));value=obj.get(key);ret(TRUE if value is True else 0)
  elif pc==0x100004180:outcomes.append(True);u.emu_stop()
  elif pc==0x1000041a4:outcomes.append(False);u.emu_stop()
  elif 0x100053808<=pc<=0x100055000:raise AssertionError(f'Unmodelled external dependency {pc:#x}')
 base_path='/private/var/db/com.apple.xpc.launchd';outcomes=[]
 u.hook_add(UC_HOOK_CODE,hook);setr('sp',0x20003f000);setr('lr',0x200000f00)
 u.emu_start(0x100046f98,0x200000f00,count=20000);assert getr('pc')==0x200000f00
 loaded=struct.unpack('<Q',bytes(u.mem_read(0x100076818,8)))[0];assert loaded in objects
 domain=0x200010000;putq(domain+0x3b8,loaded);u.mem_write(0x200011000,label.encode()+b'\0')
 # Run the real job-import gate with default Disabled=false, ForceEnableHack=false,
 # and force-import flags clear. Its real lookup helper executes unchanged.
 setr('sp',0x20003f000);setr('x22',domain);setr('x27',0x200011000);setr('x20',0);setr('x25',0);setr('x28',0)
 u.emu_start(0x100004140,0x200000f00,count=1000);assert outcomes==[disabled],(uid,label,outcomes)
 results.append(dict(label=label,file_uid=uid,disabled=outcomes[0],events=events))
a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(dict(launchd_sha256=sha,policy_sha256=hashlib.sha256(data).hexdigest(),cases=results,filesystem_and_libxpc_APIs_substituted=True,hardware_policy_accepted=False),indent=2)+'\n')
print('PASS: original launchd loader, UID/mode validation, override lookup and default job-import gate; root policy skips watchdogd only; OS APIs substituted')
