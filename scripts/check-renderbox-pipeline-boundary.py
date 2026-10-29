#!/usr/bin/env python3
"""Qualify the exact original pipeline-library crash, not a renderer frame."""
import runpy
import sys
from pathlib import Path
script=Path(__file__).with_name('check-offline-metal-sharing.py');saved=sys.argv;sys.argv=[str(script),'--depth-stencil']
try:n=runpy.run_path(str(script))
finally:sys.argv=saved
ROOT=n['ROOT'];require=n['require'];load=n['load'];sha=n['sha'];struct=n['struct'];json=n['json'];subprocess=n['subprocess']
folder=ROOT/'build/offline-renderbox-draw';build=load(folder/'build-report.json');data=load(folder/'data-report.json')
require(sha(folder/'air-native')==build['process_sha256']==data['process_sha256'] and sha(folder/'test-inputs.json')==build['manifest_sha256']==data['manifest_sha256'] and
    sha(folder/'compiler-data-32.cdr')==data['sha256'] and sha(folder/'offline-trust.bundle')==build['trust_bundle_sha256'] and
    sha(folder/'NativeOfflineMetal.bundle/NativeOfflineMetal')==build['plugin_sha256'],'Exact actual own original-renderer instrument, bundle, Data and trust')
for name,digest in load(folder/'test-inputs.json')['sources'].items():require(sha(ROOT/name)==digest,'Exact actual executed drawing source '+name)
for path in (folder/'air-native',folder/'NativeOfflineMetal.bundle'):subprocess.run(['codesign','--verify','--strict',path],check=True,timeout=30,capture_output=True)
p=ROOT/'build/darwinboot-owner-hvf-offline-renderbox-draw-cpu-contexts/gdb-stop.json';d=load(p)
require(d['kernel_sha256']==n['plan']['candidate_sha256'] and not d['bounded_timeout_interrupted'] and d['stop_symbol']=='_exception_triage' and
    d['native_4k_mmu_observed'] and d['original_amfi_table_owner_observed'] and d['owner_root_binding_audit']['boot_root_accepted'] and
    d['actual_signature_failures']==dict(_cs_validate_page_bad_hash=0,_cs_validate_page_no_hash=0) and d['actual_process']['pid']>1 and
    d['scratch_data']['actual_seed_sha256']==data['sha256'] and d['trust_cache_bundle_sha256']==build['trust_bundle_sha256'],
    'Real original-runtime renderer fault, native CPU 4K, preserved original AMFI/root and exact actual inputs')
u=d['entry_user_state_candidates'][0];registers=struct.unpack_from('<33Q',bytes.fromhex(u['saved_bytes']),8);slide=d['actual_process']['shared_region_slide'];pc=int(u['user_pc'],16)-slide
require(u['pointer']==d['actual_process']['user_state'] and not int(u['cpsr'],16)&31 and int(d['observed_function_entry_arguments'][0],16)==1 and
    pc==0x187acab64 and int(u['far'],16)==0x10 and registers[23]==0 and int(u['esr'],16)>>26==0x24 and
    any(int(f['lr'],16)-slide==0x1e2618924 for f in u['frames']),
    'Actual original Metal pipeline-loader null internal object and exact original RenderBox caller; not own EL0 success breakpoint')
a=runpy.run_path(str(ROOT/'scripts/audit-target-metal-device.py'));require(bytes.fromhex(u['instruction_bytes'])==a['read'](pc,32),'All observed fault instructions equal unchanged original target cache bytes')
broker=d['native_gpu_broker'];require(broker['requests']==40 and broker['reply_bytes']==1632 and not broker['failures'] and not broker['refusals'],
    'Captured renderer boundary genuinely advances beyond supported attachment/state requests without transport refusal')
n['cpu_contexts'](d,tuple(r['pid'] for r in broker['actual_cpu_contexts']))
log=folder/'host-cpu-contexts-stderr.log';require('Command encoder released without endEncoding' in log.read_text() and not (folder/'host-cpu-contexts-report.json').stat().st_size,
    'Actual interrupted-encoder cleanup assertion and missing partial host ledger are preserved as a failure, not successful rendering')
(n['OUT']/'renderbox-pipeline-boundary.json').write_text(json.dumps(dict(candidate_sha256=d['kernel_sha256'],report_sha256=sha(p),
    actual_original_cache_fault_pc=hex(pc),null_internal_field_address='0x10',actual_original_caller='newPipelineLibraryWithFilePath:error:',
    interrupted_encoder_cleanup_failed=True,original_renderbox_frame=False,original_desktop=False,adreno_execution=False,active_native_adreno_4k=False),indent=2)+'\n')
print('PASS: exact original RenderBox pipeline-library fault and interrupted-encoder cleanup failure qualified; no renderer frame claimed')
