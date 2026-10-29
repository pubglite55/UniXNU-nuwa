#!/usr/bin/env python3
"""Observe actual original Sandbox scoped IOKit access without changing original apps."""
import argparse,hashlib,json,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);a=p.parse_args()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
if subprocess.run(['pgrep','-f','qemu-system-aarch64'],capture_output=True).returncode==0:raise SystemExit('Another QEMU is running')
kind='offline-sandbox-extension';out=ROOT/'build'/kind
fixture=ROOT/'build'/('darwinboot-owner-hvf-'+kind)
if (fixture/'gdb-stop.json').exists():raise SystemExit('Preserve the existing observation before another run')
manifest=json.loads((out/'test-inputs.json').read_text())
for name,digest in manifest['sources'].items():
 if sha(ROOT/name)!=digest:raise SystemExit('Exact actual instrument source required: '+name)
base=ROOT/'build/xnu-prelink/native-owner-accelerator-abi-candidate';plan=json.loads(base.with_suffix('.json').read_text())
if sha(base.with_suffix('.macho'))!=plan['candidate_sha256']:raise SystemExit('Exact immutable candidate required')
cmd=['python3',str(ROOT/'scripts/probe-darwinboot-xnu.py'),'--kernel',str(base.with_suffix('.macho')),'--prelink-report',str(base.with_suffix('.json')),'--output',str(fixture),
 '--virtio-udif-image','.cache/firmware/target-volumes/044-76040-038.dmg','--virtio-extra-block-image','.cache/firmware/target-volumes/044-76034-038.dmg',
 '--virtio-mmio-fdt','build/virtio-block-fixture/qemu-virt.dtb','--root-match-volume-uuid','04769D26-2CA0-4825-B443-E2E5F88300F2',
 '--trust-cache',str(out/'offline-trust.bundle'),'--armvirt','--armcpu','--qemu-vmm-present','--qemu-accel','hvf','--owned-memory-size','0x20000000',
 '--nvram-proxy','--crypto-hash-method','sha2-384','--amfi-platform-only','--load-apfs','--load-iogpu','--inspect-owner-root','--inspect-dyld-flags','--check-commpage',
 '--skip-initializer-traces','--timeout','60','--data-ramdisk',str(out/'compiler-data-32.cdr'),'--qemu-ramfb','--inspect-boot-video',
 '--load-mobile-graphics','--mobile-graphics-client-probe','--legacy-display-phase','4','--legacy-display-gop','--legacy-display-register','--legacy-display-unit-scale',
 '--legacy-display-logical-pm','--legacy-display-validate','--legacy-display-transfer','--inspect-gop-scanout-bytes','1920000',
 '--native-air-init','--break-symbol','_exception_triage','--entry-process-name','air-native','--entry-register-equals','0:6','--inspect-current-process','--inspect-entry-user-state','--read-saved-user-register','13:100',
 '--read-saved-user-register','14:1000','--capture-qemu-screen']
cmd+=['--legacy-display-retire']
subprocess.run(cmd,cwd=ROOT,check=True,timeout=180)
print('Actual original Sandbox scoped authorization observation captured; inspect real issue/consume/open/release outcomes')
