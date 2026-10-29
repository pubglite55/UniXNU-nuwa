#!/usr/bin/env python3
"""Run the unchanged bics boot-environment branch offline with explicit API stand-ins."""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--daemon',type=Path,required=True);p.add_argument('--python-modules',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
sys.path[:0]=[str(a.python_modules),str(ROOT/'kits/XnuPrelink')]
from native_prelink import macho,backed_offset
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_SP,UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X29,UC_ARM64_REG_LR,UC_ARM64_REG_PC,UC_ARM64_REG_CPACR_EL1
raw=a.daemon.read_bytes();sha=hashlib.sha256(raw).hexdigest();assert sha=='2d1f67b75fb33d091396c70aee627bb6a2c8dcdb03ffa7401378b7a688088b53';m=macho(raw)
def at(va,size):return raw[backed_offset(m['segments'],va,size,len(raw)):][:size]
assert at(0x100002658,4)==struct.pack('<I',0x940020f5)
assert at(0x10000b0b1,21).split(b'\0')[0]==b'IODeviceTree:/chosen'
assert at(0x10000b0a0,17).split(b'\0')[0]==b'darwinos-ramdisk'
results=[]
for name,data,expected in [('missing',None,'NULL_CFData'),('normal',b'main\0','normal_continue'),('ramdisk',b'darwinos-ramdisk\0','ramdisk_wait'),('oversize',b'x'*65,'normal_continue')]:
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 for s in m['segments']:
  if s['name']=='__PAGEZERO' or not s['size']:continue
  u.mem_map(s['va'],(s['size']+4095)&~4095);u.mem_write(s['va'],raw[s['fileoff']:s['fileoff']+s['filesize']])
 u.mem_map(0x200000000,0x20000);u.reg_write(UC_ARM64_REG_SP,0x200010000);u.reg_write(UC_ARM64_REG_X29,0x200010110);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
 u.mem_write(0x100010240,struct.pack('<Q',0x200000100));u.mem_write(0x100010308,struct.pack('<Q',0x200000108));outcome={};events=[]
 def cstring(addr):
  value=bytearray()
  for i in range(128):
   ch=bytes(u.mem_read(addr+i,1))
   if ch==b'\0':break
   value.extend(ch)
  return bytes(value)
 def hook(uc,pc,size,_):
  def reg(r):return uc.reg_read(r)
  def ret(value=0):uc.reg_write(UC_ARM64_REG_X0,value);uc.reg_write(UC_ARM64_REG_PC,reg(UC_ARM64_REG_LR))
  if pc==0x100002830:outcome['result']='normal_continue';uc.emu_stop()
  elif pc==0x10000ad44:ret()
  elif pc==0x10000ab10:uc.mem_write(reg(UC_ARM64_REG_X1),struct.pack('<I',42));ret()
  elif pc==0x10000abb8:assert cstring(reg(UC_ARM64_REG_X1))==b'IODeviceTree:/chosen';ret(123)
  elif pc==0x10000abac:
   assert reg(UC_ARM64_REG_X0)==123 and reg(UC_ARM64_REG_X1)==0x100010948
   # Exact original CFString backing reference resolves to osenvironment.
   pointer=struct.unpack('<Q',at(0x100010958,8))[0]&((1<<36)-1);pointer+=0x100000000
   assert at(pointer,14).split(b'\0')[0]==b'osenvironment'
   ret(0x200000200 if data is not None else 0)
  elif pc==0x10000aa2c:
   events.append('CFDataGetLength')
   if not reg(UC_ARM64_REG_X0):outcome['result']='NULL_CFData';uc.emu_stop()
   else:ret(len(data))
  elif pc==0x10000aa20:assert reg(UC_ARM64_REG_X2)==len(data);uc.mem_write(reg(UC_ARM64_REG_X3),data);ret()
  elif pc==0x10000af3c:ret(0 if bytes(uc.mem_read(reg(UC_ARM64_REG_X0),reg(UC_ARM64_REG_X2)))==bytes(uc.mem_read(reg(UC_ARM64_REG_X1),reg(UC_ARM64_REG_X2))) else 1)
  elif pc in (0x10000aa50,0x10000ab7c,0x10000aedc):ret()
  elif pc==0x10000af84:outcome['result']='ramdisk_wait';uc.emu_stop()
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x1000025f8,0,count=2000);assert outcome.get('result')==expected,(name,outcome)
 results.append(dict(case=name,outcome=outcome['result'],events=events))
a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(dict(passed=True,daemon_sha256=sha,original_instructions=True,external_IORegistry_CF_and_signal_APIs_substituted=True,hardware_executed=False,UI_root_cause_proven=False,cases=results),indent=2)+'\n')
print('PASS: original bics branch reproduces missing-property NULL CFData, accepts main, and distinguishes intentional ramdisk wait; API stand-ins, no hardware claim')
