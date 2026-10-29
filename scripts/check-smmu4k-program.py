#!/usr/bin/env python3
"""Qualify actual context programming code offline; never open a device."""
import hashlib,json,re,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'kits/XnuPrelink'))
from native_prelink import macho
kit=ROOT/'kits/ArmSmmu4K';out=ROOT/'build/arm-smmu-4k-program';out.mkdir(exist_ok=True)
pins=json.loads((ROOT/'scripts/data/adreno-inputs.json').read_text());cache=ROOT/'.cache/adreno-source'
names=['drivers/iommu/arm/arm-smmu/arm-smmu.h','drivers/iommu/arm/arm-smmu/arm-smmu.c']
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
for name in names:
 if sha(cache/name)!=pins['linux']['files'][name]['sha256']:raise SystemExit('Pinned source differs: '+name)
header=(cache/names[0]).read_text();implementation=(cache/names[1]).read_text()
definitions={}
for text in [header,implementation]:
 for match in re.finditer(r'^#define\s+(\w+)(\([^\n]*?\))?\s+((?:[^\n]*\\\n)*[^\n]*)',text,re.M):
  definitions[match[1]]=match[0]
registers=['ARM_SMMU_GR0_ID0','ARM_SMMU_GR0_ID1','ARM_SMMU_GR0_ID2','ARM_SMMU_CB_SCTLR',
 'ARM_SMMU_CB_TCR2','ARM_SMMU_CB_TTBR0','ARM_SMMU_CB_TTBR1','ARM_SMMU_CB_TCR',
 'ARM_SMMU_CB_S1_MAIR0','ARM_SMMU_CB_S1_MAIR1','ARM_SMMU_CB_FSR','ARM_SMMU_CB_S1_TLBIASID',
 'ARM_SMMU_CB_TLBSYNC','ARM_SMMU_CB_TLBSTATUS','ARM_SMMU_CB_FSR_FAULT','ARM_SMMU_GR1_CBA2R(0)','QCOM_DUMMY_VAL']
selected={}
def include(name):
 if name in selected:return
 if name not in definitions:raise SystemExit('Missing actual source definition '+name)
 selected[name]=definitions[name]
 for dependency in set(re.findall(r'ARM_SMMU_[A-Z0-9_]+',definitions[name]))-{name}:include(dependency)
for expression in registers:include(expression.split('(')[0])
oracle=out/'source-registers.c'
oracle.write_text('#include <stdint.h>\n#define BIT(n) (UINT32_C(1)<<(n))\n#define GENMASK(h,l) ((UINT32_MAX>>(31-(h))) & (UINT32_MAX<<(l)))\n'+
 '\n'.join(selected.values())+'\nuint32_t source_register(unsigned i){const uint32_t r[]={'+','.join(registers)+'};return r[i];}\n')
# Check the pinned writer's required TCR-before-TTBR ordering, independently
# of our event fixture. This is source evidence, not timing or MMIO evidence.
writer=implementation[implementation.index('void arm_smmu_write_context_bank'):]
writer=writer[:writer.index('\n}',writer.index('{'))+2]
if not writer.index('ARM_SMMU_CB_TCR2')<writer.index('ARM_SMMU_CB_TCR,')<writer.index('ARM_SMMU_CB_TTBR0')<writer.rindex('ARM_SMMU_CB_SCTLR'):
 raise SystemExit('Original writer order differs')
sources=[kit/(name+'.c') for name in ['ArmSmmu4K','ArmSmmu4KContext','ArmSmmu4KProgram','ArmSmmu4KMmio']]
test=out/'test-program'
subprocess.run(['xcrun','clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-DSOURCE_ORACLE',*sources,kit/'test_program.c',oracle,'-o',test],check=True,timeout=60)
result=subprocess.run([test],check=True,capture_output=True,text=True,timeout=30);print(result.stdout,end='')
if '86 I/O failure controls' not in result.stdout:raise SystemExit('Failure injection coverage differs')
objects=[];imports={};provided=set()
flags=['-target','arm64-apple-ios17.0','-O2','-Wall','-Wextra','-Werror','-Wno-incompatible-sysroot','-ffreestanding','-mgeneral-regs-only']
for source in sources:
 obj=out/(source.stem+'.o')
 subprocess.run(['xcrun','clang',*flags,'-std=c11','-c',source,'-o',obj],check=True,timeout=30)
 raw=obj.read_bytes();info=macho(raw);version=next(at for command,at,_ in info['commands'] if command==0x32)
 if struct.unpack_from('<4I',raw)!=(0xfeedfacf,0x100000c,0,1) or struct.unpack_from('<II',raw,version+8)!=(2,0x110000):raise SystemExit('Ordinary ARM64 / iOS17 object required')
 imports[obj.name]=subprocess.check_output(['xcrun','nm','-u',obj],text=True).split()
 provided.update(line.split()[-1] for line in subprocess.check_output(['xcrun','nm','-gU',obj],text=True).splitlines() if line.split())
 objects.append(obj)
unexpected=set(sum(imports.values(),[]))-provided-{'___stack_chk_fail','___stack_chk_guard'}
if unexpected:raise SystemExit('Unexpected native runtime imports: '+repr(unexpected))
assembly=out/'ArmSmmu4KMmio.s'
subprocess.run(['xcrun','clang',*flags,'-std=c11','-S',sources[-1],'-o',assembly],check=True,timeout=30)
asm=assembly.read_text()
if not re.search(r'\bdsb\s+sy\b',asm) or not re.search(r'\bldr\s+x\d+,\s*\[',asm) or not re.search(r'\bstr\s+x\d+,\s*\[',asm):raise SystemExit('Native direct accesses/barrier absent')
boundary=out/'boundary.cpp'
boundary.write_text('''#include "ArmSmmu4KMmio.h"
extern "C" ArmSmmu4KStatus smmu_program_boundary(ArmSmmu4KMmio *mapping,unsigned bank,const ArmSmmu4KContextConfig *config,ArmSmmu4KProgramResult *result,bool disable) {
 ArmSmmu4KIo io;auto status=ArmSmmu4KBindMmio(mapping,&io);
 if(status!=ArmSmmu4KSuccess)return status;
 return disable?ArmSmmu4KDisableOwnedContext(&io,bank,config,1000,result):ArmSmmu4KProgramDisabledContext(&io,bank,config,1000,result);
}
''')
consumer=out/'boundary.o'
subprocess.run(['xcrun','clang++',*flags,'-std=c++17','-I',kit,'-c',boundary,'-o',consumer],check=True,timeout=30)
boundary_imports=set(subprocess.check_output(['xcrun','nm','-u',consumer],text=True).split())
if boundary_imports-{'___stack_chk_fail','___stack_chk_guard'}!={'_ArmSmmu4KBindMmio','_ArmSmmu4KProgramDisabledContext','_ArmSmmu4KDisableOwnedContext'}:raise SystemExit('Actual C++/C call boundary differs')
archive=out/'libArmSmmu4KProgram.a';subprocess.run(['xcrun','ar','rcs',archive,*objects],check=True,timeout=30)
report=dict(checker_sha256=sha(Path(__file__)),linux_revision=pins['linux']['commit'],pinned_sources={name:sha(cache/name) for name in names},source_oracle_sha256=sha(oracle),
 sources={str(p.relative_to(ROOT)):sha(p) for p in [*sources,*[kit/(s.stem+'.h') for s in sources],kit/'test_program.c']},
 objects={p.name:sha(p) for p in objects},archive_sha256=sha(archive),undefined_imports=imports,boundary_imports=sorted(boundary_imports),
 ordinary_arm64_ios17=True,general_registers_only=True,direct_aarch64_accesses_and_barrier=True,software_io_failure_controls=86,
 register_spacing_tested=[4096,65536],translation_granule_bytes=4096,software_fixture_only=True,hardware_mmio_performed=False,
 hardware_ids_observed=False,active_gpu_context_qualified=False,physical_table_ownership_qualified=False,gpu_execution_qualified=False,metal_qualified=False)
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: pinned source register definitions, programming/disable failure paths and native ARM64/iOS17 archive/C++ boundary; no hardware qualification')
