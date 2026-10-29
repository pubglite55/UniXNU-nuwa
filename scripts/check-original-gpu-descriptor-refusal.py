#!/usr/bin/env python3
"""Qualify genuine original client cleanup after an explicit absent descriptor."""
import argparse,hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def require(ok,why):
 if not ok:raise SystemExit(why)
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--candidate-base',type=Path,default=ROOT/'build/xnu-prelink/native-owner-original-descriptor-refusal-candidate');args=p.parse_args();base=args.candidate_base.resolve()
subprocess.run(['python3',ROOT/'scripts/check-original-gpu-client-factory.py','--candidate-base',base],check=True,timeout=30)
plan=load(base.with_suffix('.json'));contract=load(ROOT/'build/gpu-analysis/original-iogpu-client-contract.json');rows=[]
for kind in (1,0xabcd0001):
 folder=ROOT/'build'/('darwinboot-owner-hvf-original-client-descriptor-refusal-'+hex(kind));report=folder/'gdb-stop.json';d=load(report);sink=load(folder/'console-sink.json');provider=d['native_original_provider']
 require(d['kernel_sha256']==plan['candidate_sha256'] and not d['bounded_timeout_interrupted'] and d['qemu_accelerator']=='hvf' and d['native_4k_mmu_observed'] and not d['sheng_hardware_tested'] and d['stop_symbol']=='_native_original_provider_checkpoint','Actual bounded absent-descriptor observation')
 require(d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'] and sink['protocol_responses_sent']==0 and 0<=sink['bytes_observed']<=65536 and not sink['errors'] and not sink['gpu_execution'] and not sink['system_device_published'],'Real original crypto and response-free console control')
 broker=d['native_gpu_broker'];console=d['native_console_globals']
 require(broker['stage']==3 and not broker['status'] and not broker['clients'] and not broker['requests'] and not broker['actual_cpu_contexts'] and not any(d['native_gpu_shared_events'].values()) and all(console['_native_console_'+name]==0 for name in ('tx_requests','rx_requests','failures','tx_bytes','rx_bytes')),'Zero actual GPU commands, broker clients or shared capabilities')
 require(provider['stage']==3 and provider['status']==provider['factory_result']==0xe00002c9-(1<<32) and provider['factory_returned']==provider['descriptor_refused']==1 and not provider['factory_out_client'],'Original factory returned genuine failure with NULL output after actual absent descriptor')
 require(provider['allocated']==provider['initialized']==provider['parent_match']==provider['released']==1 and provider['size']==736 and provider['client_type']==kind and provider['callback']==170 and not provider['attached'] and not provider['registered'] and not provider['start_returned'] and not provider['start_result'],'Actual real initialization/refusal and fully detached unpublished provider release')
 require(provider['instances_live']==provider['instances_before']+1 and provider['instances_after']==provider['instances_before'] and provider['client_instances_at_callback']==provider['client_instances_before']+1 and provider['client_instances_live']==provider['client_instances_before'],'Both actual original client and own provider instance counts restored after genuine original error/cleanup')
 frame=provider['frame'];require(frame[0]==provider['object'] and frame[1] and frame[9]==int(contract['first_required_callback_caller_lr'],16),'Actual absent-descriptor callback comes from original client call site')
 registers={name:int(value,16) for name,value in d['system_registers'].items()}
 for tcr,sctlr,ttbr0,ttbr1 in ((frame[10],frame[11],frame[12],frame[13]),(registers['TCR_EL1'],registers['SCTLR_EL1'],registers['TTBR0_EL1'],registers['TTBR1_EL1'])):
  require((tcr>>14)&3==0 and (tcr>>30)&3==2 and sctlr&1 and ttbr0 and ttbr1,'Actual native CPU4K translation both at callback and after original cleanup')
 require(frame[14]%16==0 and 'factory_client_capture' not in provider,'Real original SP alignment; observer never dereferences freed client storage')
 rows.append(dict(open_type=kind,report_sha256=sha(report),original_result=provider['factory_result'],client_count_restored=True,provider_count_restored=True))
(ROOT/'build/native-original-provider/descriptor-refusal-checkpoint.json').write_text(json.dumps(dict(candidate_sha256=plan['candidate_sha256'],native_sha256=plan['native_sha256'],observations=rows,actual_original_error_cleanup=True,absent_descriptor=True,backend_resources_implemented=False,successful_client_start=False,successful_provider_start=False,normal_device_discovery=False,original_desktop=False,adreno_execution=False,active_native_adreno_4k=False),indent=2)+'\n')
print('PASS: genuine NULL descriptor refusal executes original client failure/detach/release; both original-client/provider counts restored, output NULL, nativeCPU4K and no GPU traffic')
print('Real backend resources, successful startup, original desktop and Adreno/SMMU remain unimplemented/unqualified')
