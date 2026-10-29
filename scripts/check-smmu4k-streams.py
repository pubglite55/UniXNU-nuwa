#!/usr/bin/env python3
"""Native SMMUv2 exact stream binding; original-source oracle and software MMIO."""
import hashlib,json,re,struct,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];kit=ROOT/'kits/ArmSmmu4K';out=ROOT/'build/arm-smmu-4k-streams'
out.mkdir(exist_ok=True);(out/'report.json').unlink(missing_ok=True)
pins=json.loads((ROOT/'scripts/data/adreno-inputs.json').read_text());cache=ROOT/'.cache/adreno-source'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
names=['drivers/iommu/arm/arm-smmu/arm-smmu.h','drivers/iommu/arm/arm-smmu/arm-smmu.c']
for name in names:
 if sha(cache/name)!=pins['linux']['files'][name]['sha256']:raise SystemExit('Pinned source differs '+name)
h=(cache/names[0]).read_text();c=(cache/names[1]).read_text();defs={}
for match in re.finditer(r'^#define\s+(\w+)(\([^\n]*?\))?\s+((?:[^\n]*\\\n)*[^\n]*)',h,re.M):defs[match[1]]=match[0]
selected={}
def include(name):
 if name in selected:return
 selected[name]=defs[name]
 for dep in set(re.findall(r'ARM_SMMU_[A-Za-z0-9_]+',defs[name]))-{name}:include(dep)
registers=['ARM_SMMU_GR0_sCR0','ARM_SMMU_GR0_ID0','ARM_SMMU_GR0_sGFSR','ARM_SMMU_GR0_SMR(2)','ARM_SMMU_GR0_S2CR(2)',
 'ARM_SMMU_SMR_VALID','ARM_SMMU_S2CR_EXIDVALID','ARM_SMMU_sCR0_USFCFG']
for key in registers+['ARM_SMMU_SMR_ID','ARM_SMMU_SMR_MASK','ARM_SMMU_S2CR_TYPE','ARM_SMMU_S2CR_PRIVCFG','ARM_SMMU_S2CR_CBNDX','ARM_SMMU_FEAT_EXIDS']:include(key.split('(')[0])
def block(source,signature):
 start=source.index(signature);at=source.index('{',start)+1;depth=1
 while depth:
  if source[at]=='{':depth+=1
  elif source[at]=='}':depth-=1
  at+=1
 return source[start:at]
prelude='''#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (UINT32_C(1)<<(n))
#define GENMASK(h,l) ((UINT32_MAX>>(31-(h))) & (UINT32_MAX<<(l)))
#define FIELD_PREP(mask,value) (((u32)(value)<<__builtin_ctz(mask))&(mask))
'''+ '\n'.join(selected.values())+'\n'
for signature in ['enum arm_smmu_s2cr_type {','enum arm_smmu_s2cr_privcfg {','struct arm_smmu_smr {','struct arm_smmu_s2cr {']:
 prelude+=block(h,signature)+';\n'
prelude+='''struct arm_smmu_device;
struct arm_smmu_impl {void (*write_s2cr)(struct arm_smmu_device *,int);};
struct arm_smmu_device {struct arm_smmu_smr *smrs;struct arm_smmu_s2cr *s2crs;unsigned features;const struct arm_smmu_impl *impl;};
static u32 sink_smr,sink_s2cr;
static void arm_smmu_gr0_write(struct arm_smmu_device *s,unsigned reg,u32 value) {
 (void)s;if(reg==ARM_SMMU_GR0_SMR(0))sink_smr=value;else if(reg==ARM_SMMU_GR0_S2CR(0))sink_s2cr=value;
}
'''
oracle=out/'original-streams.c';oracle.write_text(prelude+block(c,'static void arm_smmu_write_smr(')+'\n'+block(c,'static void arm_smmu_write_s2cr(')+'''
void source_stream(unsigned exid,unsigned sid,unsigned mask,unsigned valid,unsigned bank,u32 *smr,u32 *s2cr) {
 struct arm_smmu_smr m={.mask=mask,.id=sid,.valid=valid};
 struct arm_smmu_s2cr r={.type=S2CR_TYPE_TRANS,.privcfg=S2CR_PRIVCFG_DEFAULT,.cbndx=bank};
 struct arm_smmu_device s={&m,&r,exid?ARM_SMMU_FEAT_EXIDS:0,NULL};
 arm_smmu_write_s2cr(&s,0);arm_smmu_write_smr(&s,0);*smr=sink_smr;*s2cr=sink_s2cr;
}
uint32_t source_stream_register(unsigned i){const uint32_t r[]={'''+','.join(registers)+'''};return r[i];}
''')
sources=[kit/(n+'.c') for n in ['ArmSmmu4K','ArmSmmu4KContext','ArmSmmu4KProgram','ArmSmmu4KStreams']]
test=out/'test-streams';subprocess.run(['xcrun','clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
 '-DSOURCE_ORACLE',*sources,kit/'test_streams.c',oracle,'-o',test],check=True,timeout=60)
r=subprocess.run([test],check=True,capture_output=True,text=True,timeout=30);print(r.stdout,end='');(out/'host.log').write_text(r.stdout)
flags=['-target','arm64-apple-ios17.0','-O2','-Wall','-Wextra','-Werror','-Wno-incompatible-sysroot','-ffreestanding','-mgeneral-regs-only']
objdump=Path(subprocess.check_output(['brew','--prefix','llvm'],text=True).strip())/'bin/llvm-objdump'
objects=[];provided=set();imports=set()
for source in sources:
 obj=out/(source.stem+'.o');subprocess.run(['xcrun','clang',*flags,'-std=c11','-c',source,'-o',obj],check=True,timeout=30)
 raw=obj.read_bytes()
 if struct.unpack_from('<4I',raw)!=(0xfeedfacf,0x100000c,0,1):raise SystemExit('Ordinary ARM64 required')
 at=32;ios17=False
 for _ in range(struct.unpack_from('<I',raw,16)[0]):
  cmd,size=struct.unpack_from('<II',raw,at)
  if cmd==0x32:ios17=struct.unpack_from('<II',raw,at+8)==(2,0x110000)
  at+=size
 if not ios17:raise SystemExit('iOS17 ABI required')
 imports.update(subprocess.check_output(['xcrun','nm','-u',obj],text=True).split())
 provided.update(re.findall(r'^[0-9a-f]+ [A-Z] (\S+)$',subprocess.check_output(['xcrun','nm','-gU',obj],text=True),re.M))
 asm=subprocess.check_output([objdump,'-d',obj],text=True)
 operands='\n'.join(re.findall(r'^[ \t]*[0-9a-f]+:[ \t]+[0-9a-f]{8}[ \t]+\w+[ \t]+([^\n]+)',asm,re.M))
 if re.search(r'\b(?:[qds][0-9]+|v[0-9]+(?:\.[0-9a-z]+)?)\b',operands):raise SystemExit('SIMD found')
 objects.append(obj)
imports-=provided
if imports-{'___stack_chk_fail','___stack_chk_guard','_memset'}:raise SystemExit('Unexpected imports '+repr(imports))
analysis=subprocess.run(['xcrun','clang','--analyze','-std=c11',*sources,'-Xanalyzer','-analyzer-output=text'],capture_output=True,text=True,timeout=60)
if analysis.returncode or analysis.stderr:raise SystemExit('Analyzer diagnostics: '+analysis.stderr)
archive=out/'libArmSmmu4KStreams.a';archive.unlink(missing_ok=True);subprocess.run(['xcrun','ar','rcs',archive,*objects],check=True,timeout=30)
inputs=sources+[kit/(s.stem+'.h') for s in sources]+[kit/'test_streams.c',Path(__file__)]
report=dict(passed=True,linux_revision=pins['linux']['commit'],pinned_sources={n:sha(cache/n) for n in names},
 sources={str(p.relative_to(ROOT)):sha(p) for p in inputs},oracle_sha256=sha(oracle),objects={p.name:sha(p) for p in objects},
 archive_sha256=sha(archive),native_imports=sorted(imports),host_asan_ubsan=True,ordinary_arm64_ios17=True,actual_instructions_without_simd=True,
 static_analysis_clean=True,software_peer_only=True,active_hardware_mapping_qualified=False,hardware_ready=False)
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: original stream writer/register oracle and native archive; no hardware qualification')
