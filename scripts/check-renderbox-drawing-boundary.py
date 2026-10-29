#!/usr/bin/env python3
"""Verify a genuine original-renderer refusal, never treat it as a frame."""
import json
from pathlib import Path
import runpy
import struct
import sys
script=Path(__file__).with_name('check-offline-metal-sharing.py');saved=sys.argv;sys.argv=[str(script),'--renderbox-device']
try:n=runpy.run_path(str(script))
finally:sys.argv=saved
ROOT=n['ROOT'];require=n['require'];load=n['load'];sha=n['sha']
folder=ROOT/'build/offline-renderbox-draw';build=load(folder/'build-report.json');data=load(folder/'data-report.json')
require(sha(folder/'air-native')==build['process_sha256']==data['process_sha256'] and
    sha(folder/'test-inputs.json')==build['manifest_sha256']==data['manifest_sha256'] and
    sha(folder/'compiler-data-32.cdr')==data['sha256'] and sha(folder/'offline-trust.bundle')==build['trust_bundle_sha256'],
    'Exact own drawing diagnostic, signed inputs and mutable Data')
for name,digest in load(folder/'test-inputs.json')['sources'].items():require(sha(ROOT/name)==digest,'Exact actual drawing source '+name)
require(sha(folder/'NativeOfflineMetal.bundle/NativeOfflineMetal')==build['plugin_sha256'],'Actual own partial plugin')
report=ROOT/'build/darwinboot-owner-hvf-offline-renderbox-draw-cpu-contexts/gdb-stop.json';d=load(report)
require(d['kernel_sha256']==n['plan']['candidate_sha256'] and not d['bounded_timeout_interrupted'] and
    d['stop_symbol']=='_exception_triage' and d['native_4k_mmu_observed'] and d['original_amfi_table_owner_observed'] and
    d['owner_root_binding_audit']['boot_root_accepted'] and d['actual_process']['pid']>1 and
    d['actual_signature_failures']==dict(_cs_validate_page_bad_hash=0,_cs_validate_page_no_hash=0) and
    d['scratch_data']['actual_seed_sha256']==data['sha256'] and d['trust_cache_bundle_sha256']==build['trust_bundle_sha256'],
    'Real original-runtime drawing worker, native CPU 4K, unchanged original AMFI and authenticated root')
u=d['entry_user_state_candidates'][0];v=struct.unpack('<32Q',bytes.fromhex(u['register_memory']['13:100']['bytes']))
reason=bytes.fromhex(u['register_memory']['14:200']['bytes']).split(b'\0')[0].decode()
require(u['pointer']==d['actual_process']['user_state'] and u['instruction_bytes'].startswith('000020d4') and
    int(u['cpsr'],16)&31==0 and v[:6]==(0x52424641,d['actual_process']['pid'],4096,4096,64,24) and
    reason.startswith('Actual uncaught NSInvalidArgumentException: -[OMQueueObject getGPUPriority]: unrecognized selector sent to instance '),
    'Actual original drawing worker raises the precise missing queue-priority selector; own handler records refusal and stops')
rows=d['native_gpu_broker']['actual_cpu_contexts'];n['cpu_contexts'](d,tuple(r['pid'] for r in rows))
require(d['native_gpu_broker']['requests']==8 and not d['native_gpu_broker']['failures'] and not d['native_gpu_broker']['refusals'],
    'Observed early boundary precedes the subsequent sharing/completion test')
(n['OUT']/'renderbox-drawing-refusal.json').write_text(json.dumps(dict(report_sha256=sha(report),
    own_process_sha256=build['process_sha256'],candidate_sha256=d['kernel_sha256'],reason=reason,
    original_renderbox_device_initialized=True,original_renderbox_frame_qualified=False,
    original_desktop=False,adreno_execution=False,active_native_adreno_4k=False),indent=2)+'\n')
print('PASS: precise real RenderBox drawing refusal captured; no renderer frame or desktop is qualified')
