#!/usr/bin/env python3
"""Qualify native4K upper tables and SMMUv2 context encoding, without MMIO."""
import hashlib,json,re,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'kits/XnuPrelink'))
from native_prelink import macho
kit=ROOT/'kits/ArmSmmu4K';out=ROOT/'build/arm-smmu-4k-context';out.mkdir(exist_ok=True)
pins=json.loads((ROOT/'scripts/data/adreno-inputs.json').read_text());revision=pins['linux']['commit']
source_root=ROOT/'.cache/adreno-source'
names=['drivers/iommu/arm/arm-smmu/arm-smmu.h','drivers/iommu/arm/arm-smmu/arm-smmu.c',
 'drivers/iommu/arm/arm-smmu/arm-smmu-qcom.c','drivers/iommu/io-pgtable-arm.c','include/linux/io-pgtable.h']
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
for name in names:
 if sha(source_root/name)!=pins['linux']['files'][name]['sha256']:raise SystemExit('Pinned actual SMMU source differs: '+name)
header=(source_root/names[0]).read_text();functions=[]
for name in ('arm_smmu_lpae_tcr','arm_smmu_lpae_tcr2'):
 match=re.search(r'static inline u32 '+name+r'\([^\n]+\)\n\{[\s\S]*?\n\}',header)
 if not match:raise SystemExit('Cannot extract actual original inline helper '+name)
 functions.append(match[0])
macro_names=set(re.findall(r'ARM_SMMU_[A-Z0-9_]+','\n'.join(functions)));macros=[]
for name in sorted(macro_names):
 match=re.search(r'^#define\s+'+name+r'\s+[^\n]+',header,re.M)
 if not match:raise SystemExit('Cannot extract original helper register field '+name)
 macros.append(match[0])
quirk=re.search(r'^\s*#define IO_PGTABLE_QUIRK_ARM_TTBR1\s+[^\n]+',(source_root/'include/linux/io-pgtable.h').read_text(),re.M)
if not quirk:raise SystemExit('Actual source TTBR1 quirk absent')
# These two function bodies/field definitions are the exact pinned source,
# compiled separately. The small local harness provides only their input types
# and kernel bit primitives. The original source copy stays ignored.
prelude='''#include <stdint.h>
typedef uint32_t u32;
#define BIT(n) (UINT32_C(1)<<(n))
#define GENMASK(h,l) ((UINT32_MAX>>(31-(h))) & (UINT32_MAX<<(l)))
#define FIELD_PREP(mask,val) (((uint32_t)(val)<<__builtin_ctz((uint32_t)(mask))) & (mask))
struct io_pgtable_cfg {unsigned quirks;struct {struct {unsigned tg,sh,orgn,irgn,tsz,ips;} tcr;} arm_lpae_s1_cfg;};
'''
harness='''
uint32_t source_tcr(unsigned bits,unsigned upper,unsigned coherent) {
 struct io_pgtable_cfg c={0};c.quirks=upper?IO_PGTABLE_QUIRK_ARM_TTBR1:0;
 c.arm_lpae_s1_cfg.tcr.tg=upper?2:0;c.arm_lpae_s1_cfg.tcr.sh=coherent?3:2;
 c.arm_lpae_s1_cfg.tcr.orgn=coherent?1:0;c.arm_lpae_s1_cfg.tcr.irgn=coherent?1:0;
 c.arm_lpae_s1_cfg.tcr.tsz=64-bits;return arm_smmu_lpae_tcr(&c);
}
uint32_t source_tcr2(unsigned output_code) {
 struct io_pgtable_cfg c={0};c.arm_lpae_s1_cfg.tcr.ips=output_code;
 return arm_smmu_lpae_tcr2(&c);
}
'''
oracle=out/'source-oracle.c';oracle.write_text(prelude+'\n'.join([quirk[0],*macros,*functions])+harness)
sources=[kit/'ArmSmmu4K.c',kit/'ArmSmmu4KContext.c']
test=out/'test-context'
subprocess.run(['xcrun','clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',*sources,kit/'test_context.c',oracle,'-o',test],check=True,timeout=60)
result=subprocess.run([test],check=True,capture_output=True,text=True,timeout=30);print(result.stdout,end='')
match=re.search(r'(\d+) context images.*; (\d+) one-bit readback refusals; (\d+) TCR2.TBI/SCTLR.ASIDPNE readback tolerances',result.stdout)
if not match or tuple(map(int,match.groups()))!=(7344,2805408,36720):raise SystemExit('Actual bounded test counts differ')
objects=[];imports={}
for source in sources:
 obj=out/(source.stem+'.o')
 subprocess.run(['xcrun','clang','-target','arm64-apple-ios17.0','-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-incompatible-sysroot','-ffreestanding','-mgeneral-regs-only','-c',source,'-o',obj],check=True,timeout=30)
 raw=obj.read_bytes();image=macho(raw);version=next(at for command,at,_ in image['commands'] if command==0x32)
 if struct.unpack_from('<4I',raw)!=(0xfeedfacf,0x100000c,0,1) or image['kind']!=1 or struct.unpack_from('<II',raw,version+8)!=(2,0x110000):raise SystemExit('Actual ARM64 subtype0 / iOS17 object required')
 undefined=set(subprocess.check_output(['xcrun','nm','-u',obj],text=True).split())
 if not undefined<={'___stack_chk_fail','___stack_chk_guard'}:raise SystemExit('Unexpected native runtime imports: '+repr(undefined))
 objects.append(obj);imports[obj.name]=sorted(undefined)
boundary=out/'boundary.cpp';boundary.write_text('''#include "ArmSmmu4KContext.h"
extern "C" ArmSmmu4KStatus smmu_context_boundary(const ArmSmmu4KConfig *c,const ArmSmmu4KRange *r,uint64_t *tables,ArmSmmu4KResult *result,const ArmSmmu4KContextConfig *context,ArmSmmu4KContextImage *image) {
 auto status=ArmSmmu4KBuildUpper(c,r,1,tables,32,result);
 return status==ArmSmmu4KSuccess?ArmSmmu4KEncodeContext(context,image):status;
}
''')
consumer=out/'boundary.o';subprocess.run(['xcrun','clang++','-target','arm64-apple-ios17.0','-std=c++17','-O2','-Wall','-Wextra','-Werror','-Wno-incompatible-sysroot','-ffreestanding','-mgeneral-regs-only','-I',kit,'-c',boundary,'-o',consumer],check=True,timeout=30)
undefined=set(subprocess.check_output(['xcrun','nm','-u',consumer],text=True).split())
if undefined!={'_ArmSmmu4KBuildUpper','_ArmSmmu4KEncodeContext'}:raise SystemExit('Actual unmangled C++/C boundary differs')
archive=out/'libArmSmmu4KContext.a';subprocess.run(['xcrun','ar','rcs',archive,*objects],check=True,timeout=30)
report=dict(checker_sha256=sha(Path(__file__)),linux_revision=revision,pinned_source_sha256={name:sha(source_root/name) for name in names},source_oracle_sha256=sha(oracle),
 sources={str(path.relative_to(ROOT)):sha(path) for path in [*sources,kit/'ArmSmmu4K.h',kit/'ArmSmmu4KContext.h',kit/'test_context.c']},
 objects={path.name:sha(path) for path in objects},archive_sha256=sha(archive),undefined_imports=imports,ordinary_arm64_ios17=True,general_registers_only=True,
 upper_address_widths=list(range(32,49)),context_images_checked=7344,readback_bit_refusals=2820096,granule_bytes=4096,encoded_ttbr0_and_ttbr1_granule_bytes=4096,
 physical_ids_observed=False,actual_smmu_state_observed=False,tables_activated=False,mmio_writes=False,gpu_execution_qualified=False,metal_qualified=False)
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: pinned original SMMUv2 TCR equations, native4K TTBR0/TTBR1, complete context image/refusals and ARM64/iOS17 C++ boundary; no MMIO or active GPU qualification')
