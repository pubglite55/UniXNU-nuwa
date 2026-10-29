#!/usr/bin/env python3
"""Qualify modern GMU HFI transport against pinned source, entirely offline."""
import hashlib,json,re,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'kits/XnuPrelink'))
from native_prelink import macho
kit=ROOT/'kits/AdrenoFirmware';out=ROOT/'build/adreno-hfi';out.mkdir(exist_ok=True)
pins=json.loads((ROOT/'scripts/data/adreno-inputs.json').read_text());cache=ROOT/'.cache/adreno-source'
names=['drivers/gpu/drm/msm/adreno/a6xx_hfi.c','drivers/gpu/drm/msm/adreno/a6xx_hfi.h']
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
for name in names:
 p=cache/name;pin=pins['linux']['files'][name]
 if sha(p)!=pin['sha256'] or p.stat().st_size!=pin['bytes']:raise SystemExit('Actual pinned HFI source differs: '+name)
source=(cache/names[0]).read_text();header=(cache/names[1]).read_text()
def function(signature):
 start=source.index(signature);opening=source.index('{',start);level=1;at=opening+1
 while level:
  if source[at]=='{':level+=1
  elif source[at]=='}':level-=1
  at+=1
 return source[start:at]
wire=[]
for name in ['a6xx_hfi_queue_table_header','a6xx_hfi_queue_header']:
 match=re.search(r'struct '+name+r' \{[\s\S]*?\} __packed;',header)
 if not match:raise SystemExit('Original shared wire struct absent')
 wire.append(match[0])
# The original layout and queue functions are compiled unchanged in an ignored
# oracle. Only irrelevant Linux locks/history runtime and MMIO notification are
# stubbed in this SOFTWARE reference. It cannot operate a real device.
prelude='''#include <stdint.h>
#include <errno.h>
#include <string.h>
typedef uint32_t u32;typedef uint64_t u64;typedef int32_t s32;typedef uint8_t u8;
#define __packed __attribute__((packed))
#define HFI_MAX_QUEUES 3
#define HFI_HISTORY_SZ 8
#define SZ_4K 4096
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define CIRC_SPACE(h,t,s) (((t)-(h)-1)&((s)-1))
#define READ_ONCE(v) (v) /* single-thread software oracle only */
#define WRITE_ONCE(v,x) ((v)=(x))
#define spin_lock_init(v) ((void)(v))
#define spin_lock(v) ((void)(v))
#define spin_unlock(v) ((void)(v))
#define atomic_set(v,x) (*(v)=(x))
#define dma_mb() __sync_synchronize()
#define WARN_ON(x) ((void)(x))
#define REG_A6XX_GMU_HOST2GMU_INTR_SET 0
#define gmu_write(g,r,v) ((void)(g),(void)(r),(void)(v))
'''
standins='''
struct a6xx_hfi_queue {struct a6xx_hfi_queue_header *header;u32 *data;int lock,seqnum;s32 history[8];u8 history_idx;};
struct a6xx_gmu_bo {void *virt;u64 iova;};
struct a6xx_gmu {struct a6xx_gmu_bo hfi;struct a6xx_hfi_queue queues[3];int legacy;};
'''
wrappers='''
void source_initialize(u32 *shared,u32 iova) {
 struct a6xx_gmu g={0};g.hfi.virt=shared;g.hfi.iova=iova;a6xx_hfi_init(&g);
}
int source_write(u32 *shared,u32 iova,u32 *message,u32 count) {
 struct a6xx_gmu g={0};g.hfi.virt=shared;g.hfi.iova=iova;
 g.queues[0].header=(void *)(shared+6);g.queues[0].data=shared+1024;
 return a6xx_hfi_queue_write(&g,&g.queues[0],message,count);
}
'''
oracle=out/'original-hfi-oracle.c'
oracle.write_text(prelude+'\n'.join(wire)+standins+'\n'.join([
 function('static int a6xx_hfi_queue_write('),function('static void a6xx_hfi_queue_init('),function('void a6xx_hfi_init(')])+wrappers)
test=out/'test-hfi'
subprocess.run(['xcrun','clang','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-DSOURCE_ORACLE',kit/'AdrenoHfi.c',kit/'test_hfi.c',oracle,'-o',test],check=True,timeout=60)
result=subprocess.run([test],check=True,capture_output=True,text=True,timeout=30);print(result.stdout,end='')
if '510 modern HFI wrapped command/response cases, 4100 sequence exchanges' not in result.stdout:raise SystemExit('Actual bounded coverage differs')
flags=['-target','arm64-apple-ios17.0','-O2','-Wall','-Wextra','-Werror','-Wno-incompatible-sysroot','-ffreestanding','-mgeneral-regs-only']
obj=out/'AdrenoHfi.o';subprocess.run(['xcrun','clang',*flags,'-std=c11','-c',kit/'AdrenoHfi.c','-o',obj],check=True,timeout=30)
raw=obj.read_bytes();info=macho(raw);version=next(at for command,at,_ in info['commands'] if command==0x32)
if struct.unpack_from('<4I',raw)!=(0xfeedfacf,0x100000c,0,1) or struct.unpack_from('<II',raw,version+8)!=(2,0x110000):raise SystemExit('Actual ordinary ARM64/iOS17 object required')
undefined=set(subprocess.check_output(['xcrun','nm','-u',obj],text=True).split())
if undefined-{'___stack_chk_fail','___stack_chk_guard'}:raise SystemExit('Unexpected native runtime imports: '+repr(undefined))
assembly=out/'AdrenoHfi.s';subprocess.run(['xcrun','clang',*flags,'-std=c11','-S',kit/'AdrenoHfi.c','-o',assembly],check=True,timeout=30)
asm=assembly.read_text()
for barrier in ['dmb\\s+oshld','dmb\\s+osh\\b','dsb\\s+oshst']:
 if not re.search(barrier,asm):raise SystemExit('Actual AArch64 shared-memory barrier absent: '+barrier)
boundary=out/'boundary.cpp';boundary.write_text('''#include "AdrenoHfi.h"
extern "C" AdrenoHfiStatus hfi_boundary(AdrenoHfi *h,volatile uint32_t *shared,uint64_t iova,void *cookie,int (*notify)(void *),uint32_t *response,size_t *count,uint32_t *error) {
 auto result=AdrenoHfiInitializeStopped(h,shared,16384,iova,cookie,notify);
 return result==AdrenoHfiSuccess?AdrenoHfiExchange(h,14,nullptr,0,100,nullptr,response,16,count,error):result;
}
''')
consumer=out/'boundary.o';subprocess.run(['xcrun','clang++',*flags,'-std=c++17','-I',kit,'-c',boundary,'-o',consumer],check=True,timeout=30)
boundary_imports=set(subprocess.check_output(['xcrun','nm','-u',consumer],text=True).split())
if boundary_imports-{'___stack_chk_fail','___stack_chk_guard'}!={'_AdrenoHfiInitializeStopped','_AdrenoHfiExchange'}:raise SystemExit('Real C++/C boundary differs')
archive=out/'libAdrenoHfi.a';subprocess.run(['xcrun','ar','rcs',archive,obj],check=True,timeout=30)
report=dict(checker_sha256=sha(Path(__file__)),linux_revision=pins['linux']['commit'],pinned_sources={n:sha(cache/n) for n in names},original_oracle_sha256=sha(oracle),
 original_oracle_only_software=True,sources={str(p.relative_to(ROOT)):sha(p) for p in [kit/'AdrenoHfi.c',kit/'AdrenoHfi.h',kit/'test_hfi.c']},
 object_sha256=sha(obj),archive_sha256=sha(archive),boundary_sha256=sha(consumer),undefined_imports=sorted(undefined),boundary_imports=sorted(boundary_imports),
 ordinary_arm64_ios17=True,general_registers_only=True,wrapped_command_response_cases=510,sequence_exchanges=4100,
 shared_bytes=16384,native4k_pages_required=4,software_peer_only=True,actual_gmu_ack_observed=False,hardware_mmio_performed=False,
 active_native4k_gpu_mappings_qualified=False,coherency_qualified=False,power_or_firmware_startup_qualified=False,gpu_execution_qualified=False)
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: original pinned HFI layout/serialization oracle and native ARM64/iOS17 transport; actual GMU startup remains unqualified')
