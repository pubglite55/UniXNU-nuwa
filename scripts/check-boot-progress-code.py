#!/usr/bin/env python3
"""Inspect real ARM64 instructions; compile all hook callers with hooks disabled."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

root=Path(__file__).resolve().parents[1]
out=root/'build/ufs-root-diagnostics/progress/code'
out.mkdir(parents=True,exist_ok=True)
(out/'report.json').unlink(missing_ok=True)
objdump=shutil.which('llvm-objdump') or '/opt/homebrew/opt/llvm/bin/llvm-objdump'
nm=shutil.which('llvm-nm') or '/opt/homebrew/opt/llvm/bin/llvm-nm'
objects=[root/'build/boot-progress/BootProgress.o',root/'build/boot-progress/BootFaultProbe.o',root/'build/boot-progress/BootWatchdogPolicy.o',root/'build/sheng-ufs/NativeUfs.o',root/'build/native-legacy-display/BootUiTraceProbe.o']
for obj in objects:
    text=subprocess.check_output([objdump,'-d',str(obj)],text=True,timeout=30)
    operands='\n'.join(re.findall(r'^[ \t]*[0-9a-f]+:[ \t]+[0-9a-f]{8}[ \t]+\w+[ \t]+([^\n]+)',text,re.M))
    assert not re.search(r'\b(?:[qds][0-9]+|v[0-9]+(?:\.[0-9a-z]+)?)\b',operands), 'Unexpected FP/SIMD in IRQ-reachable diagnostic'
    assert not re.search(r'\bmsr\s+(?:TCR_EL1|TTBR[01]_EL1|SCTLR_EL1)',text), 'Observer object cannot directly modify translation'
    (out/(obj.stem+'.asm')).write_text(text)
    if obj.stem=='BootProgress':
        assert len(re.findall(r'\bmrs\s+x\d+, CNTPCT_EL0',text))>=4, 'Actual counter reads are required, not just source asm strings'
        assert re.search(r'\bmrs\s+x\d+, CNTFRQ_EL0',text)
        assert re.search(r'msr\s+DAIFSet, #0xf\s*\n.*dsb\s+sy',text), 'Freeze must mask IRQs AND complete framebuffer stores'
        assert 'wfe' in text
base=root/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
checked=[]
for area,names in [('osfmk',['arm_init','startup','video_console','serial_console','sleh']),
                   ('bsd',['bsd_init','kern_exec','kern_exit']),('pexpert',['pe_kprintf'])]:
    for name in names:
        r=json.loads((base/area/'DEVELOPMENT'/(name+'.o.json')).read_text().strip().rstrip(','))
        cmd=[];a=r['arguments'];i=0;obj=out/(name+'.off.o')
        while i<len(a):
            value=a[i]
            if value in ('-o','-MF','-MT','-MJ'):
                if value=='-o':cmd+=['-o',str(obj)]
                i+=1
            elif value=='-D' and a[i+1].startswith('XNU_BOOT_PROGRESS='):i+=1
            elif not value.startswith('-DXNU_BOOT_PROGRESS='):cmd.append(value)
            i+=1
        cmd+=['-DXNU_BOOT_PROGRESS=0']
        with (out/(name+'.off.log')).open('w') as f:
            subprocess.run(cmd,cwd=r['directory'],stdout=f,stderr=subprocess.STDOUT,check=True,timeout=90)
        undefined=subprocess.check_output([nm,'-u',str(obj)],text=True,timeout=10)
        assert '_boot_progress_' not in undefined, name+' keeps a diagnostic dependency when disabled'
        checked.append(area+'/'+name)
(out/'report.json').write_text(json.dumps({'passed':True,'disabled_callers':checked,
    'objects':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in objects},
    'counter_instructions_present':True,'fp_simd_absent':True,'translation_writes_absent':True,
    'hardware_observed':False},indent=2)+'\n')
print('PASS: actual counter/barrier instructions, no FP/SIMD or translation writes; all nine callers compile without diagnostic imports when disabled')
