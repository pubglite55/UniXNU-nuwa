#!/usr/bin/env python3
"""Independent source oracle for native A7xx ARC/BCM configuration arithmetic."""
import hashlib,json,re,struct,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];kit=ROOT/'kits/AdrenoFirmware';cache=ROOT/'.cache/adreno-source'
disassembler=Path(subprocess.check_output(['brew','--prefix','llvm'],text=True).strip())/'bin/llvm-objdump'
out=ROOT/'build/adreno-hfi-votes';out.mkdir(exist_ok=True);(out/'report.json').unlink(missing_ok=True)
pins=json.loads((ROOT/'scripts/data/adreno-inputs.json').read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
names=['drivers/gpu/drm/msm/adreno/'+s for s in ['a6xx_gmu.c','a6xx_gmu.h','a6xx_hfi.c','a6xx_hfi.h']]+['include/soc/qcom/tcs.h']
for n in names:
 if sha(cache/n)!=pins['linux']['files'][n]['sha256']:raise SystemExit('Pinned source differs '+n)
gmu=(cache/names[0]).read_text();hfi=(cache/names[2]).read_text()
def function(source,signature):
 start=source.index(signature);at=source.index('{',start)+1;depth=1
 while depth:
  if source[at]=='{':depth+=1
  elif source[at]=='}':depth-=1
  at+=1
 return source[start:at]
# Linux environment adapters below are confined to an ignored single-thread
# software oracle. Original arithmetic/layout functions themselves are intact.
tcs=(cache/names[4]).read_text();tcs=tcs[tcs.index('#define BCM_TCS_CMD_COMMIT_MASK'):tcs.index('#endif')]
gmuh=(cache/names[1]).read_text();bcm=gmuh[gmuh.index('struct a6xx_bcm {'):gmuh.index('\n};',gmuh.index('struct a6xx_bcm {'))+3]
db=gmu[gmu.index('struct bcm_db {'):gmu.index('\n};',gmu.index('struct bcm_db {'))+3]
prelude='''#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "AdrenoHfiVotes.h"
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef int32_t s32;
typedef uint16_t __le16;typedef uint32_t __le32;typedef int spinlock_t;typedef int atomic_t;
#define __packed __attribute__((packed))
#define BIT(n) (1u<<(n))
#define GENMASK(h,l) ((UINT32_MAX>>(31-(h)))& (UINT32_MAX<<(l)))
static u32 u32_encode_bits(u32 value,u32 mask){return (value<<__builtin_ctz(mask))&mask;}
#define IS_ERR(p) ((p)==NULL)
#define PTR_ERR(p) (-1)
#define EINVAL 22
#define DRM_DEV_ERROR(...) ((void)0)
#define dev_err(...) ((void)0)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define do_div(n,d) ((n)/=(d))
#define clamp(v,lo,hi) ((v)<(lo)?(lo):(v)>(hi)?(hi):(v))
#define GMU_MAX_BCMS 3
'''+tcs+'\n'+(cache/names[3]).read_text()+'\n'+bcm+'\n'+db+'''
struct device {int unused;};struct adreno_gpu {int unused;};
struct a6xx_info {const struct a6xx_bcm *bcms;};
struct a6xx_gmu {struct device *dev;unsigned nr_gpu_bws;u32 gpu_bw_table[16],gpu_ib_votes[16][3];};
static int adreno_is_a7xx(const struct adreno_gpu *g){(void)g;return 1;}
static int adreno_is_a8xx(const struct adreno_gpu *g){(void)g;return 0;}
static const u32 *opp_levels;static u16 rails[2][256];static size_t rail_sizes[2];
static struct bcm_db aux[3];static u32 addrs[3],cn0;
static const void *cmd_db_read_aux_data(const char *name,size_t *count) {
 if(name[0]=='p' || name[0]=='s'){unsigned i=name[0]=='s';*count=rail_sizes[i];return rails[i];}
 unsigned i=(unsigned)(name[0]-'0');*count=sizeof(aux[i]);return aux+i;
}
static u32 cmd_db_read_addr(const char *name){return name[0]=='C'?cn0:addrs[name[0]-'0'];}
static unsigned a6xx_gmu_get_arc_level(struct device *dev,unsigned long freq){(void)dev;return opp_levels[freq];}
'''
wrapper='''
int source_arc(const u32 *levels,unsigned count,const u8 *p,size_t pn,const u8 *s,size_t sn,u32 *votes) {
 unsigned long freq[16];opp_levels=levels;rail_sizes[0]=pn;rail_sizes[1]=sn;
 memcpy(rails[0],p,pn);memcpy(rails[1],s,sn);for(unsigned i=0;i<count;++i)freq[i]=i;
 return a6xx_gmu_rpmh_arc_votes_init(NULL,votes,freq,(int)count,"p","s");
}
int source_bandwidth(const u32 *bw,unsigned count,const AdrenoHfiBcm *b,unsigned n,u32 address,u32 out[159]) {
 struct a6xx_bcm policy[4]={0};struct a6xx_info info={policy};struct a6xx_gmu g={0};
 struct adreno_gpu gpu={0};char names[3][2]={{'0',0},{'1',0},{'2',0}};
 for(unsigned j=0;j<n;++j){policy[j]=(struct a6xx_bcm){names[j],b[j].buswidth,b[j].fixed,b[j].perfmode,b[j].perfmode_kbps};
 aux[j]=(struct bcm_db){b[j].unit,b[j].width,b[j].vcd,0};addrs[j]=b[j].address;}
 cn0=address;g.nr_gpu_bws=count;memcpy(g.gpu_bw_table,bw,count*4);
 int status=a6xx_gmu_rpmh_bw_votes_init(&gpu,&info,&g);if(status)return status;
 struct a6xx_hfi_msg_bw_table msg={0};a6xx_generate_bw_table(&info,&g,&msg);
 memcpy(out,(u8 *)&msg+4,sizeof(msg)-4);return 0;
}
'''
oracle=out/'original-votes-oracle.c';oracle.write_text(prelude+
 function(gmu,'static int a6xx_gmu_rpmh_arc_votes_init(')+'\n'+
 function(gmu,'static int a6xx_gmu_rpmh_bw_votes_init(')+'\n'+
 function(hfi,'static void a6xx_generate_bw_table(')+wrapper)
sources=[kit/'AdrenoHfiVotes.c',kit/'AdrenoHfiStartup.c',kit/'AdrenoHfi.c',kit/'test_votes.c']
test=out/'test-votes';subprocess.run(['xcrun','clang','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-sign-compare',
 '-fsanitize=address,undefined','-I',kit,*sources,oracle,'-o',test],check=True,timeout=60)
r=subprocess.run([test],check=True,capture_output=True,text=True,timeout=30);print(r.stdout,end='');(out/'host.log').write_text(r.stdout)
obj=out/'AdrenoHfiVotes.o';flags=['-target','arm64-apple-ios17.0','-O2','-Wall','-Wextra','-Werror','-Wno-incompatible-sysroot','-ffreestanding','-mgeneral-regs-only']
subprocess.run(['xcrun','clang',*flags,'-std=c11','-c',sources[0],'-o',obj],check=True,timeout=30)
raw=obj.read_bytes()
if struct.unpack_from('<4I',raw)!=(0xfeedfacf,0x100000c,0,1):raise SystemExit('Not ordinary ARM64 object')
at=32;ios17=False
for _ in range(struct.unpack_from('<I',raw,16)[0]):
 cmd,size=struct.unpack_from('<II',raw,at)
 if cmd==0x32:ios17=struct.unpack_from('<II',raw,at+8)==(2,0x110000)
 at+=size
if not ios17:raise SystemExit('Not iOS17 ABI')
imports=set(subprocess.check_output(['xcrun','nm','-u',obj],text=True).split())
if imports-{'___stack_chk_fail','___stack_chk_guard'}:raise SystemExit('Unexpected import '+repr(imports))
asm=subprocess.check_output([disassembler,'-d',obj],text=True)
operands='\n'.join(re.findall(r'^[ \t]*[0-9a-f]+:[ \t]+[0-9a-f]{8}[ \t]+\w+[ \t]+([^\n]+)',asm,re.M))
if re.search(r'\b(?:[qds][0-9]+|v[0-9]+(?:\.[0-9a-z]+)?)\b',operands):raise SystemExit('SIMD in native code')
report=dict(passed=True,linux_revision=pins['linux']['commit'],pinned_sources={n:sha(cache/n) for n in names},
 sources={str(p.relative_to(ROOT)):sha(p) for p in sources+[kit/'AdrenoHfiVotes.h',Path(__file__)]},oracle_sha256=sha(oracle),
 object_sha256=sha(obj),arc_source_cases=1000,bcm_source_cases=1000,host_asan_ubsan=True,ordinary_arm64_ios17=True,
 actual_instructions_without_simd=True,actual_platform_inputs_collected=False,hardware_ready=False)
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: A7xx votes native object; no platform-data or power-transition qualification')
