#!/usr/bin/env python3
"""Offline modern HFI startup: source oracle, actual queue transport, native ABI."""
import hashlib,json,re,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
disassembler=Path(subprocess.check_output(['brew','--prefix','llvm'],text=True).strip())/'bin/llvm-objdump'
kit=ROOT/'kits/AdrenoFirmware';out=ROOT/'build/adreno-hfi-startup';out.mkdir(exist_ok=True)
(out/'report.json').unlink(missing_ok=True)
pins=json.loads((ROOT/'scripts/data/adreno-inputs.json').read_text());cache=ROOT/'.cache/adreno-source'
names=['drivers/gpu/drm/msm/adreno/'+n for n in ['a6xx_hfi.c','a6xx_hfi.h','a6xx_gmu.h']]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for name in names:
 if sha(cache/name)!=pins['linux']['files'][name]['sha256']:raise SystemExit('Pinned source mismatch '+name)
source=(cache/names[0]).read_text()
def function(signature):
 start=source.index(signature);at=source.index('{',start)+1;depth=1
 while depth:
  if source[at]=='{':depth+=1
  elif source[at]=='}':depth-=1
  at+=1
 return source[start:at]
header=(cache/names[1]).read_text()
# Original functions below stay in ignored storage. Only the software oracle's
# platform/types/message sink are substituted; it never performs device I/O.
prelude='''#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "AdrenoHfiStartup.h"
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef int32_t s32;
typedef int spinlock_t;typedef int atomic_t;
#define __packed __attribute__((packed))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define DRM_DEV_ERROR(...) ((void)0)
'''+header+'''
#define GMU_IDLE_STATE_IFPC 3
struct adreno_gpu {int unused;};
struct a6xx_gmu {
 int legacy,nr_gpu_freqs,nr_gmu_freqs,idle_level;void *dev;
 u64 gpu_freqs[16],gmu_freqs[4];u32 gx_arc_votes[16],cx_arc_votes[4];
 struct a6xx_hfi_acd_table acd_table;struct a6xx_hfi_msg_bw_table bw;
};
struct a6xx_gpu {struct adreno_gpu base;struct a6xx_gmu gmu;};
static int adreno_is_a8xx(const struct adreno_gpu *gpu){(void)gpu;return 0;}
static int a8xx_hfi_send_perf_table(struct a6xx_gmu *gmu){(void)gmu;return -1;}
static int a6xx_hfi_start_v1(struct a6xx_gmu *gmu,int boot){(void)gmu;(void)boot;return -1;}
static unsigned *sink_count,*sink_ids,*sink_words,fail_at;static u32 (*sink_data)[159];
static int a6xx_hfi_send_msg(struct a6xx_gmu *g,int id,void *msg,u32 bytes,u32 *output,u32 capacity) {
 (void)g;(void)output;(void)capacity;unsigned i=(*sink_count)++;
 if(i>=8 || bytes<4 || bytes>640 || bytes%4)return -1;
 sink_ids[i]=(unsigned)id;sink_words[i]=bytes/4-1;memcpy(sink_data[i],(u32 *)msg+1,bytes-4);
 return fail_at==i+1?-1:0;
}
static int a6xx_hfi_send_bw_table(struct a6xx_gmu *g) {
 return a6xx_hfi_send_msg(g,HFI_H2F_MSG_BW_TABLE,&g->bw,sizeof(g->bw),NULL,0);
}
#define IFPC_LONG_HYST 0x1680
'''
if '#define GMU_IDLE_STATE_IFPC 3' not in (cache/names[2]).read_text() or '#define IFPC_LONG_HYST 0x1680' not in source:raise SystemExit('Pinned IFPC policy changed')
functions=['static int a6xx_hfi_send_perf_table(','static int a6xx_hfi_feature_ctrl_msg(',
 'static int a6xx_hfi_enable_ifpc(','static int a6xx_hfi_enable_acd(',
 'static int a6xx_hfi_send_start(','static int a6xx_hfi_send_core_fw_start(','int a6xx_hfi_start(']
wrapper='''
int source_startup(const AdrenoHfiStartupConfig *c,unsigned fail,unsigned *count,unsigned *ids,unsigned *words,u32 data[8][159]) {
 struct a6xx_gpu gpu={0};struct a6xx_gmu *g=&gpu.gmu;
 g->nr_gpu_freqs=c->gpu_count;g->nr_gmu_freqs=c->gmu_count;
 for(unsigned i=0;i<c->gpu_count;++i){g->gpu_freqs[i]=c->gpu[i].hz;g->gx_arc_votes[i]=c->gpu[i].vote;}
 for(unsigned i=0;i<c->gmu_count;++i){g->gmu_freqs[i]=c->gmu[i].hz;g->cx_arc_votes[i]=c->gmu[i].vote;}
 g->bw.bw_level_num=c->bandwidth_count;g->bw.cnoc_cmds_num=c->cnoc_count;g->bw.ddr_cmds_num=c->ddr_count;
 g->bw.cnoc_wait_bitmask=c->cnoc_wait_mask;g->bw.ddr_wait_bitmask=c->ddr_wait_mask;
 memcpy(g->bw.cnoc_cmds_addrs,c->cnoc_addresses,sizeof(c->cnoc_addresses));memcpy(g->bw.cnoc_cmds_data,c->cnoc_data,sizeof(c->cnoc_data));
 memcpy(g->bw.ddr_cmds_addrs,c->ddr_addresses,sizeof(c->ddr_addresses));memcpy(g->bw.ddr_cmds_data,c->ddr_data,sizeof(c->ddr_data));
 g->acd_table.version=c->acd_version;g->acd_table.enable_by_level=c->acd_enable_mask;g->acd_table.stride=c->acd_stride;g->acd_table.num_levels=c->acd_count;
 memcpy(g->acd_table.data,c->acd_data,sizeof(c->acd_data));g->idle_level=c->enable_ifpc?GMU_IDLE_STATE_IFPC:0;
 *count=0;sink_count=count;sink_ids=ids;sink_words=words;sink_data=data;fail_at=fail;
 return a6xx_hfi_start(g,0);
}
'''
oracle=out/'original-startup-oracle.c';oracle.write_text(prelude+'\n'.join(function(f) for f in functions)+wrapper)
sources=[kit/'AdrenoHfi.c',kit/'AdrenoHfiStartup.c',kit/'test_startup.c']
test=out/'test-startup'
subprocess.run(['xcrun','clang','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-DSOURCE_ORACLE','-I',kit,*sources,oracle,'-o',test],check=True,timeout=60)
r=subprocess.run([test],check=True,capture_output=True,text=True,timeout=30);print(r.stdout,end='');(out/'host.log').write_text(r.stdout)
flags=['-target','arm64-apple-ios17.0','-O2','-Wall','-Wextra','-Werror','-Wno-incompatible-sysroot','-ffreestanding','-mgeneral-regs-only']
objects=[]
for source in sources[:2]:
 obj=out/(source.stem+'.o');subprocess.run(['xcrun','clang',*flags,'-std=c11','-c',source,'-o',obj],check=True,timeout=30)
 raw=obj.read_bytes()
 if struct.unpack_from('<4I',raw)!=(0xfeedfacf,0x100000c,0,1):raise SystemExit('Not ordinary ARM64 object')
 at=32;ios17=False
 for _ in range(struct.unpack_from('<I',raw,16)[0]):
  cmd,size=struct.unpack_from('<II',raw,at)
  if cmd==0x32:ios17=struct.unpack_from('<II',raw,at+8)==(2,0x110000)
  at+=size
 if not ios17:raise SystemExit('Not iOS17 ABI')
 undefined=set(subprocess.check_output(['xcrun','nm','-u',obj],text=True).split())
 allowed={'___stack_chk_fail','___stack_chk_guard','_AdrenoHfiSend','_AdrenoHfiPoll','_memset'}
 if undefined-allowed:raise SystemExit('Unexpected native import '+repr(undefined))
 asm=subprocess.check_output([disassembler,'-d',obj],text=True)
 operands='\n'.join(re.findall(r'^[ \t]*[0-9a-f]+:[ \t]+[0-9a-f]{8}[ \t]+\w+[ \t]+([^\n]+)',asm,re.M))
 if re.search(r'\b(?:[qds][0-9]+|v[0-9]+(?:\.[0-9a-z]+)?)\b',operands):raise SystemExit('SIMD in actual native code')
 objects.append(obj)
boundary=out/'boundary.cpp';boundary.write_text('''#include "AdrenoHfiStartup.h"
extern "C" AdrenoHfiStartupStatus startup_boundary(AdrenoHfiStartup *s,AdrenoHfi *h,const AdrenoHfiStartupConfig *c,const AdrenoHfiStartupServices *v,AdrenoHfiStartupResult *r) {return AdrenoHfiStartupRun(s,h,c,v,r);}
''')
consumer=out/'boundary.o';subprocess.run(['xcrun','clang++',*flags,'-std=c++17','-I',kit,'-c',boundary,'-o',consumer],check=True,timeout=30)
imports=set(subprocess.check_output(['xcrun','nm','-u',consumer],text=True).split())
if imports!={'_AdrenoHfiStartupRun'}:raise SystemExit('C++/C linkage mismatch')
archive=out/'libAdrenoHfiStartup.a';archive.unlink(missing_ok=True);subprocess.run(['xcrun','ar','rcs',archive,*objects],check=True,timeout=30)
inputs=sources+[kit/'AdrenoHfi.h',kit/'AdrenoHfiStartup.h',Path(__file__)]
report=dict(passed=True,linux_revision=pins['linux']['commit'],pinned_sources={n:sha(cache/n) for n in names},
 sources={str(p.relative_to(ROOT)):sha(p) for p in inputs},oracle_sha256=sha(oracle),
 objects={str(p.relative_to(ROOT)):sha(p) for p in objects},archive_sha256=sha(archive),boundary_sha256=sha(consumer),
 startup_profiles=4,per_stage_failure_cases=66,source_serialization_and_order_match=True,
 monotonic_and_iteration_limits=True,ordinary_arm64_ios17=True,actual_instructions_without_simd=True,
 software_peer_only=True,actual_gmu_ack_observed=False,active_native4k_gpu_mappings_qualified=False,hardware_ready=False)
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: original-source startup bytes/order and failure boundaries; no hardware or GMU execution claim')
