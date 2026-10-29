#!/usr/bin/env python3
"""Run one bounded actual iOS17 compiler/control boot; this does not emulate a GPU."""
import argparse
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--case',required=True,choices=['exit','bad-input','no-trust','default-off'])
group=p.add_mutually_exclusive_group()
group.add_argument('--library-input',action='store_true',help='Read whole original OS libraries through the native compiler')
group.add_argument('--vpc-tests',action='store_true',help='Run native encoder plus original source-reference VPC tests')
group.add_argument('--library-tests',action='store_true',help='Run actual native container refusal/guard tests')
group.add_argument('--metal-runtime',action='store_true',help='Observe genuine original Metal ABI and missing provider')
p.add_argument('--fragment-inputs',action='store_true',help='Include the five new center-perspective original fragments')
a=p.parse_args()
if a.fragment_inputs and not a.library_input:p.error('Fragment inputs require direct original libraries')
if a.case=='bad-input' and (a.library_input or a.library_tests or a.metal_runtime or a.vpc_tests):p.error('Bad extracted AIR input belongs to the original compiler control')
kind='adreno-vpc-native-tests' if a.vpc_tests else 'air-fragment-inputs-diagnostic' if a.fragment_inputs else 'air-library-diagnostic' if a.library_input else 'air-library-native-tests' if a.library_tests else 'metal-runtime-diagnostic' if a.metal_runtime else 'air-nir-diagnostic'
name=('adreno-vpc-controls' if a.case=='exit' else 'adreno-vpc-controls-'+a.case) if a.vpc_tests else 'air-fragment-inputs-'+a.case if a.fragment_inputs else 'air-library-'+a.case if a.library_input else ('air-library-controls' if a.case=='exit' else 'air-library-controls-'+a.case) if a.library_tests else ('metal-runtime-complete' if a.case=='exit' else 'metal-runtime-'+a.case) if a.metal_runtime else 'air17-'+a.case
output='build/darwinboot-owner-hvf-'+name
trust='build/original-static-system-trust/original-static-system.bundle' if a.case=='no-trust' else 'build/'+kind+'/offline-trust.bundle'
data='build/'+kind+'/compiler-data'+('-bad-input' if a.case=='bad-input' else '')+'-32.cdr'
cmd=['python3','scripts/probe-darwinboot-xnu.py',
 '--kernel','build/xnu-prelink/native-owner-air-outer-candidate.macho',
 '--prelink-report','build/xnu-prelink/native-owner-air-outer-candidate.json',
 '--output',output,'--virtio-udif-image','.cache/firmware/target-volumes/044-76040-038.dmg',
 '--virtio-extra-block-image','.cache/firmware/target-volumes/044-76034-038.dmg',
 '--virtio-mmio-fdt','build/virtio-block-fixture/qemu-virt.dtb',
 '--root-match-volume-uuid','04769D26-2CA0-4825-B443-E2E5F88300F2','--trust-cache',trust,
 '--armvirt','--armcpu','--qemu-vmm-present','--qemu-accel','hvf',
 '--owned-memory-size','0x20000000','--nvram-proxy','--crypto-hash-method','sha2-384',
 '--amfi-platform-only','--load-apfs','--inspect-owner-root','--inspect-dyld-flags','--check-commpage',
 '--skip-initializer-traces','--timeout','60','--data-ramdisk',data,'--qemu-ramfb','--inspect-boot-video']
cmd+=['--follow-target-main'] if a.case=='default-off' else ['--native-air-init','--break-symbol','_exit','--read-entry-region','1:0:8']
if a.metal_runtime:cmd+=['--load-iogpu']
r=subprocess.run(cmd,cwd=ROOT,timeout=180)
if a.case=='no-trust':
 import json,struct
 d=json.loads((ROOT/output/'gdb-stop.json').read_text())
 args=struct.unpack_from('<5Q',bytes.fromhex(d['stack_bytes']))
 if r.returncode!=1 or d['stop_symbol']!='_panic' or args[2:4]!=(9,8) or not d['argument_memory']['x0'].startswith('unexpected SIGKILL of %s %s with reason'):raise SystemExit('Expected genuine EXEC security-policy refusal')
 print('PASS: absent own test trust produces genuine EXEC security-policy refusal')
else:
 if r.returncode:raise SystemExit(r.returncode)
 if a.case in ('exit','bad-input'):
  import json,struct
  d=json.loads((ROOT/output/'gdb-stop.json').read_text())
  expected=62 if a.case=='bad-input' else 93 if a.vpc_tests else 90 if a.library_tests else 74 if a.metal_runtime else 73
  if d['stop_symbol']!='_exit' or struct.unpack_from('<I',bytes.fromhex(d['entry_regions']['1:0:8']['bytes']))[0]!=expected:raise SystemExit('Unexpected actual native exit status')
  print('PASS: genuine native instrument exit status',expected)
