#!/usr/bin/env python3
"""Original LPAE permission oracle, including GMU privileged executable memory."""
import hashlib,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];cache=ROOT/'.cache/adreno-source';kit=ROOT/'kits/ArmSmmu4K'
out=ROOT/'build/arm-smmu-4k-permissions';out.mkdir(exist_ok=True);(out/'report.json').unlink(missing_ok=True)
pins=json.loads((ROOT/'scripts/data/adreno-inputs.json').read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
names=['drivers/iommu/io-pgtable-arm.c','include/linux/io-pgtable.h','include/linux/iommu.h',
 'drivers/gpu/drm/msm/msm_gem.c','drivers/gpu/drm/msm/adreno/a6xx_gmu.c']
for n in names:
 if sha(cache/n)!=pins['linux']['files'][n]['sha256']:raise SystemExit('Pinned permission source differs '+n)
source=(cache/names[0]).read_text();header=(cache/names[1]).read_text()
def block(source,sig):
 start=source.index(sig);at=source.index('{',start)+1;depth=1
 while depth:
  if source[at]=='{':depth+=1
  elif source[at]=='}':depth-=1
  at+=1
 return source[start:at]
function=block(source,'static arm_lpae_iopte arm_lpae_prot_to_pte(')
definitions={}
for text in [source,header,(cache/names[2]).read_text()]:
 for m in re.finditer(r'^\s*#define\s+(\w+)(\([^\n]*?\))?\s+((?:[^\n]*\\\n)*[^\n]*)',text,re.M):definitions[m[1]]=m[0]
selected={}
def include(name):
 if name in selected:return
 selected[name]=definitions[name]
 for dep in set(re.findall(r'(?:ARM_LPAE_|IOMMU_|IO_PGTABLE_QUIRK_)[A-Za-z0-9_]+',definitions[name]))-{name}:include(dep)
for name in set(re.findall(r'(?:ARM_LPAE_|IOMMU_|IO_PGTABLE_QUIRK_)[A-Za-z0-9_]+',function)):include(name)
prelude='''#include <stdint.h>
typedef uint64_t arm_lpae_iopte;
#define BIT(n) (1u<<(n))
'''+block(header,'enum io_pgtable_fmt {')+';\n'+'\n'.join(selected.values())+'''
struct arm_lpae_io_pgtable {struct {enum io_pgtable_fmt fmt;struct {unsigned quirks;} cfg;} iop;};
'''
oracle=out/'original-permissions.c';oracle.write_text(prelude+function+'''
uint64_t source_permission_pte(unsigned permissions,unsigned cache) {
 struct arm_lpae_io_pgtable data={.iop={.fmt=ARM_64_LPAE_S1}};
 int prot=IOMMU_READ;
 if(permissions&2)prot|=IOMMU_WRITE;
 if(!(permissions&4))prot|=IOMMU_NOEXEC;
 if(permissions&8)prot|=IOMMU_PRIV;
 if(cache)prot|=IOMMU_CACHE;
 return arm_lpae_prot_to_pte(&data,prot);
}
''')
gem=block((cache/names[3]).read_text(),'int msm_gem_prot(')
gmu=block((cache/names[4]).read_text(),'static int a6xx_gmu_memory_alloc(')
if 'MSM_BO_MAP_PRIV' not in gmu or 'MSM_BO_MAP_PRIV' not in gem or 'IOMMU_PRIV' not in gem or 'IOMMU_NOEXEC' in gem:
 raise SystemExit('Pinned GMU/MSM mapping policy changed')
sources=[kit/'ArmSmmu4K.c',kit/'test_permissions.c'];test=out/'test-permissions'
subprocess.run(['xcrun','clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',*sources,oracle,'-o',test],check=True,timeout=60)
r=subprocess.run([test],check=True,capture_output=True,text=True,timeout=30);print(r.stdout,end='')
if '544 lower/upper' not in r.stdout:raise SystemExit('Permission case count changed')
(out/'host.log').write_text(r.stdout)
(out/'report.json').write_text(json.dumps(dict(passed=True,linux_revision=pins['linux']['commit'],pinned_sources={n:sha(cache/n) for n in names},
 sources={str(p.relative_to(ROOT)):sha(p) for p in sources+[kit/'ArmSmmu4K.h',Path(__file__)]},oracle_sha256=sha(oracle),
 profiles=544,leaves=1088,host_asan_ubsan=True,cpu_permissions_modified=False,active_hardware_mapping_qualified=False),indent=2)+'\n')
