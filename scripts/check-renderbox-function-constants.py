#!/usr/bin/env python3
"""Qualify the real AIR fallback and function-constant boundary without claiming a frame."""
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
    'Real original-runtime renderer observation, native CPU 4K, original AMFI/root and exact inputs')
u=d['entry_user_state_candidates'][0];memory=u['register_memory'];v=struct.unpack('<32Q',bytes.fromhex(memory['13:100']['bytes']))
require(u['pointer']==d['actual_process']['user_state'] and not int(u['cpsr'],16)&31 and u['instruction_bytes'].startswith('000020d4') and
    v[:6]==(0x52424641,d['actual_process']['pid'],4096,4096,73,24),
    'Actual own diagnostic stops exactly at the original function-constant request, not renderer completion')
raw=bytes.fromhex(memory['14:1000']['bytes']);require(b'\0' in raw,'Complete actual diagnostic C string precedes any unavailable tail page')
detail=raw.split(b'\0',1)[0].decode();require(detail.startswith('Actual function specialization plane__vertex values class MTLFunctionConstantValuesInternal size 16') and
    'index: 0; type: MTLDataTypeUInt4; value: (2, 0, 5502022, 4)' in detail and
    'newIndexedConstantArray{@16@0:8}' in detail and 'newNamedConstantArray{@16@0:8}' in detail,
    'Original runtime supplies an actual UInt4 constant and exposes original typed accessor ABIs')
broker=d['native_gpu_broker'];require(broker['requests']==42 and broker['reply_bytes']==4878 and broker['clients']==broker['active']==2 and
    not broker['closed'] and not broker['failures'] and not broker['refusals'],'Real two-client original AIR-library fallback, still incomplete')
n['cpu_contexts'](d,tuple(r['pid'] for r in broker['actual_cpu_contexts']))
host_path=folder/'host-cpu-contexts-report.json';host=load(host_path);ops=host['operations'];libraries=[o for o in ops if o['operation']==0x102]
require(len(ops)==42 and len(libraries)==2 and len({o['session'] for o in libraries})==2 and
    all(o['handle'] and not o['error'] and o['result_bytes']==1591 for o in libraries) and
    not host['transport_healthy'] and not host['session_finished'] and not host['completed_commands'] and not host['open_encoders'],
    'Both unchanged original RenderBox AIR libraries actually load, with no completed drawing or invented success')
require(len(host['aborted_encoders'])==2 and {o['session'] for o in host['aborted_encoders']}=={o['session'] for o in libraries} and
    all(o['encoding_ended'] and o['actual_command_status']==1 and not o['gpu_submission_created_by_cleanup'] and o['reason']=='transport-lost' for o in host['aborted_encoders']),
    'Both real abandoned encoders end without committing the interrupted commands; full partial ledger retained')
require('Command encoder released without endEncoding' not in (folder/'host-cpu-contexts-stderr.log').read_text(),'No host Metal encoder-deallocation assertion')
(n['OUT']/'renderbox-function-constant-boundary.json').write_text(json.dumps(dict(candidate_sha256=d['kernel_sha256'],report_sha256=sha(p),host_report_sha256=sha(host_path),
    actual_function='plane__vertex',actual_constant_type='MTLDataTypeUInt4',actual_constant_value=[2,0,5502022,4],actual_original_air_fallback=True,
    original_renderbox_frame=False,original_desktop=False,adreno_execution=False,active_native_adreno_4k=False),indent=2)+'\n')
print('PASS: actual original AIR-library fallback and UInt4 specialization boundary; abandoned encoders cleanly end without invented GPU submission')
