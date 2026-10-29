#!/usr/bin/env python3
"""Execute original watchdogd connection branches offline, with explicit API stubs.
No VM boot, OS-byte patch, signature change, device access or hardware proof.
"""
import argparse, hashlib, json, struct, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
a=argparse.ArgumentParser(description=__doc__)
a.add_argument('--watchdogd',type=Path,required=True)
a.add_argument('--python-modules',type=Path,required=True)
a.add_argument('--report',type=Path,required=True)
args=a.parse_args();sys.path[:0]=[str(args.python_modules),str(ROOT/'kits/XnuPrelink')]
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X3,UC_ARM64_REG_LR,UC_ARM64_REG_PC,UC_ARM64_REG_SP
from native_prelink import macho,backed_offset
raw=args.watchdogd.read_bytes();sha=hashlib.sha256(raw).hexdigest()
assert sha=='ded4c688e1c2add74acf3e7f9eea5fe2c2c569180ce81492221877944d913a01','Unqualified watchdogd revision'
m=macho(raw)
def word(pc):return struct.unpack_from('<I',raw,backed_offset(m['segments'],pc,4,len(raw)))[0]
assert word(0x10000ab0c)==0xd4200020
results=[]
for name,service,vmm,open_error in [('physical_missing',0,0,0),('virtual_missing',0,1,0),('service_open_error',99,0,0xe00002c7),('service_connected',99,0,0)]:
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 for s in m['segments']:
  if s['name']=='__PAGEZERO' or not s['size']:continue
  u.mem_map(s['va'],(s['size']+4095)&~4095)
  u.mem_write(s['va'],raw[s['fileoff']:s['fileoff']+s['filesize']])
 u.mem_map(0x200000000,0x20000);u.reg_write(UC_ARM64_REG_SP,0x20001f000);u.reg_write(UC_ARM64_REG_LR,0x200000f00)
 # Bind the two imported data pointers used by the real connection body.
 for pc,destination in [(0x100006760,0x200000100),(0x10000678c,0x200000108)]:
  w=word(pc);assert w&0xff000000==0x58000000
  imm=(w>>5)&0x7ffff;imm-=0x80000 if imm&0x40000 else 0
  u.mem_write(pc+imm*4,struct.pack('<Q',destination))
 u.mem_write(0x200000108,struct.pack('<I',42))
 events=[];result={};crash_message=None
 def cstring(addr):
  b=bytearray()
  for n in range(256):
   c=bytes(u.mem_read(addr+n,1))
   if c==b'\0':break
   b.extend(c)
  return b.decode(errors='replace')
 def hook(uc,pc,size,_):
  global crash_message
  def ret(value=0):uc.reg_write(UC_ARM64_REG_X0,value);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_LR))
  if pc==0x200000f00:result.update(outcome='connected');uc.emu_stop()
  elif pc in (0x100004ebc,0x10000a1b8):events.append(cstring(uc.reg_read(UC_ARM64_REG_X1)));ret()
  elif pc==0x10000b454:assert cstring(uc.reg_read(UC_ARM64_REG_X0))=='IOWatchdog';ret(0x200000200)
  elif pc==0x10000b448:ret(service)
  elif pc==0x10000b460:
   if not open_error:uc.mem_write(uc.reg_read(UC_ARM64_REG_X3),struct.pack('<I',123))
   ret(open_error)
  elif pc==0x10000b3f4:ret()
  elif pc==0x10000bb5c:
   assert cstring(uc.reg_read(UC_ARM64_REG_X0))=='kern.hv_vmm_present'
   uc.mem_write(uc.reg_read(UC_ARM64_REG_X1),struct.pack('<I',vmm));ret()
  elif pc==0x10000b4e4:
   fmt=cstring(uc.reg_read(UC_ARM64_REG_X1));assert fmt=='IOServiceOpen failed with error : 0x%x'
   error=struct.unpack('<Q',bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_SP),8)))[0]
   payload=(fmt%error).encode()+b'\0';uc.mem_write(0x200000400,payload)
   uc.mem_write(uc.reg_read(UC_ARM64_REG_X0),struct.pack('<Q',0x200000400));ret(len(payload)-1)
  elif pc==0x100006b54:ret() # diagnostic logging
  elif pc==0x10000b4b4:crash_message=cstring(uc.reg_read(UC_ARM64_REG_X0));events.append(crash_message);ret()
  elif pc==0x10000b4a8:ret(0x200000300) # assertion log; not reached in qualified cases
  elif pc==0x10000ba54:assert uc.reg_read(UC_ARM64_REG_X0)==2;ret()
  elif pc==0x10000b61c:result.update(outcome='exit',status=uc.reg_read(UC_ARM64_REG_X0));uc.emu_stop()
  elif word_if_text(pc)==0xd4200020:result.update(outcome='brk',pc=hex(pc),message=crash_message);uc.emu_stop()
  elif 0x10000b280<=pc<0x10000bbe0:raise AssertionError(f'Unmodelled external stub {pc:#x}')
 def word_if_text(pc):
  return word(pc) if 0x100003698<=pc<0x10000b280 else 0
 u.hook_add(UC_HOOK_CODE,hook)
 # Run the real VM-query initializer once; sysctl and once scheduling are
 # substituted explicitly, then mark that exact token complete.
 u.emu_start(0x100008db4,0x200000f00,count=10000)
 result.clear();u.reg_write(UC_ARM64_REG_SP,0x20001f000);u.reg_write(UC_ARM64_REG_LR,0x200000f00)
 # The exact token address is qualified from the original LDR literal.
 w=word(0x100008d80);imm=(w>>5)&0x7ffff;imm-=0x80000 if imm&0x40000 else 0
 u.mem_write(0x100008d80+imm*4,struct.pack('<Q',0xffffffffffffffff))
 u.emu_start(0x100006748,0x200000f00,count=10000)
 if not result and u.reg_read(UC_ARM64_REG_PC)==0x200000f00:result.update(outcome='connected')
 assert result, 'Instruction bound reached'
 if name=='physical_missing':assert result['outcome']=='brk' and result['pc']=='0x10000ab0c' and 'unable to lookup' in result['message']
 elif name=='virtual_missing':assert result=={'outcome':'exit','status':0}
 elif name=='service_connected':assert result['outcome']=='connected'
 else:assert result['outcome']=='brk'
 results.append(dict(case=name,service=service,vmm=vmm,open_error=open_error,events=events,**result))
args.report.parent.mkdir(parents=True,exist_ok=True)
args.report.write_text(json.dumps(dict(watchdogd_sha256=sha,cases=results,external_APIs_stubbed=True,hardware_fault_PC_observed=False,physical_root_cause_proven=False),indent=2)+'\n')
print('PASS: unchanged watchdogd native/VM missing-service and open success/error branches; API dependencies substituted; physical branch unobserved')
