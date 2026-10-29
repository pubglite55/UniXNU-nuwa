#!/usr/bin/env python3
"""Qualify GPU pixels and original swap return separately from actual scanout."""
import hashlib
import json
from pathlib import Path
import struct
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'build/offline-legacy-swap'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def require(v,s):
    if not v:raise SystemExit(s)
def load(p):return json.loads(p.read_text())
build=load(OUT/'build-report.json');manifest=load(OUT/'test-inputs.json');data=load(OUT/'data-report.json')
require(sha(OUT/'air-native')==build['process_sha256']==data['process_sha256'] and
        sha(OUT/'test-inputs.json')==build['manifest_sha256']==data['manifest_sha256'], 'Exact own executable and manifest')
for name,digest in manifest['sources'].items():require(sha(ROOT/name)==digest,'Exact source '+name)
path=ROOT/'build/darwinboot-owner-hvf-offline-legacy-swap/gdb-stop.json';d=load(path)
require(sha(OUT/'compiler-data-32.cdr')==data['sha256']==d['scratch_data']['actual_seed_sha256'] and
        sha(OUT/'offline-trust.bundle')==build['trust_bundle_sha256']==d['trust_cache_bundle_sha256'], 'Actual own Data/trust')
def modules(raw):
    n=struct.unpack_from('<I',raw)[0];offsets=struct.unpack_from('<'+'I'*n,raw,4)
    return [raw[a:b] for a,b in zip(offsets,(*offsets[1:],len(raw)))]
require(modules((OUT/'offline-trust.bundle').read_bytes())[1:]==modules(
        (ROOT/'build/original-static-system-trust/original-static-system.bundle').read_bytes()), 'Original trust modules preserved')
plan=load(ROOT/'build/xnu-prelink/native-owner-legacy-display-scale-candidate.json')
require(d['kernel_sha256']==plan['candidate_sha256'] and d['native_4k_mmu_observed'] and
        d['original_amfi_table_owner_observed'] and d['owner_root_binding_audit']['boot_root_accepted'] and
        d['actual_signature_failures']==dict(_cs_validate_page_bad_hash=0,_cs_validate_page_no_hash=0), 'Exact candidate, AMFI/root/native 4K')
require(not d['bounded_timeout_interrupted'] and d['stop_symbol']=='_exception_triage' and
        d['actual_process']['name']=='air-native' and d['actual_process']['pid']==1,'Real own process boundary')
u=d['entry_user_state_candidates'][0];values=struct.unpack('<16Q',bytes.fromhex(u['register_memory']['13:80']['bytes']))
require(int(u['cpsr'],16)&31==0 and u['instruction_bytes'].startswith('000020d4') and
        values[:6]==(0x47505357,1,4096,4096,800,600) and values[6] and
        values[7:12]==(480000,0,1,0,0) and values[12]>0 and values[13]>=24000000 and
        values[14:]==(1,4), 'Real full GPU-pixel check, original statuses and actual one-second queue observation interval')
host=load(OUT/'host-report.json');ops=host['operations']
require(host['host_device']=='Apple M1' and not host['cpu_pixel_renderer'] and not host['adreno_execution'] and
        not host['guest_system_device_discovery'] and not host['original_desktop'] and len(ops)==609 and
        ops[0]['operation']==0x100 and ops[-1]['operation']==0x10f and
        all(o['request']==i+1 and not o['error'] for i,o in enumerate(ops)), 'Actual complete ordered host GPU session')
require(len(host['completed_commands'])==len(host['texture_readbacks'])==1, 'One real GPU frame')
command=host['completed_commands'][0];readback=host['texture_readbacks'][0]
require(command['status']==4 and 0<command['gpu_start_ns']<command['gpu_end_ns'] and
        readback['bytes']==1920000 and readback['sha256']==hashlib.sha256(struct.pack('<I',0xff336699)*480000).hexdigest(),
        'Actual GPU completion and complete pixel digest')
legacy=d['native_legacy_display']
require(legacy['stage']==10 and legacy['guard_slot']==0 and legacy['client_status']==0 and
        legacy['gop_width']==800 and legacy['gop_height']==600,'Real original client and mapped GOP')
capture=d['qemu_screen_capture'];screen=path.parent/capture['file']
require(sha(screen)==capture['sha256']=='e90f3f3195332e37f9a95d7416dc79ca2fa63d08ed3e170f71704a5678000aaf',
        'Actual scanout still matches the independently inspected previous loader frame')
(OUT/'checkpoint.json').write_text(json.dumps(dict(report_sha256=sha(path),host_report_sha256=sha(OUT/'host-report.json'),
    actual_gpu_completed=True,original_swap_api_success=True,actual_presented_gpu_frame=False,
    scanout='unchanged previous loader frame',system_metal=False,original_desktop=False,adreno_execution=False),indent=2)+'\n')
print('PASS: actual GPU frame, original IOSurface and successful original swap API returns')
print('Actual scanout remains the loader frame: presentation is not qualified')
