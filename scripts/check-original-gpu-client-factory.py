#!/usr/bin/env python3
"""Check real original client factory/task/subtype and first descriptor boundary."""
import argparse,hashlib,json,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'kits/XnuPrelink'))
from native_prelink import macho,backed_offset
def require(value,why):
 if not value:raise SystemExit(why)
def load(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--candidate-base',type=Path,default=ROOT/'build/xnu-prelink/native-owner-original-descriptor-refusal-candidate');args=p.parse_args();base=args.candidate_base.resolve()
# This independently qualifies all unchanged operational provider addresses,
# real original lifetime, required configureDevice hook and default-off boot.
subprocess.run(['python3',ROOT/'scripts/check-original-gpu-provider.py','--candidate-base',base],check=True,timeout=30)
plan=load(base.with_suffix('.json'));raw=base.with_suffix('.macho').read_bytes();segments=macho(raw)['segments']
abi=load(ROOT/'build/gpu-analysis/original-iogpu-userclient-abi.json');contract=load(ROOT/'build/gpu-analysis/original-iogpu-client-contract.json')
require(contract['original_kernel_sha256']==plan['original_sha256'] and contract['original_iogpu_text_sha256']==plan['original_executable_sha256']['com.apple.iokit.IOGPUFamily'],'Exact supplied target/client contract identity')
for field in ('new_user_client','custom_client_initialize','initialize_device','cleanup'):
 extent=contract[field];at=backed_offset(segments,int(extent['address'],16),extent['bytes'],len(raw))
 require(hashlib.sha256(raw[at:at+extent['bytes']]).hexdigest()==extent['sha256'],'Actual unchanged original executable contract '+field)
rows=[]
for kind in (1,0xabcd0001,0):
 folder=ROOT/'build'/('darwinboot-owner-hvf-original-client-factory-'+hex(kind));path=folder/'gdb-stop.json';d=load(path);sink=load(folder/'console-sink.json');provider=d['native_original_provider']
 require(d['kernel_sha256']==plan['candidate_sha256'] and not d['bounded_timeout_interrupted'] and d['qemu_accelerator']=='hvf' and d['native_4k_mmu_observed'] and not d['sheng_hardware_tested'] and d['stop_symbol']=='_native_original_provider_checkpoint','Actual bounded new-kernel factory observation')
 registers={k:int(v,16) for k,v in d['system_registers'].items()}
 require((registers['TCR_EL1']>>14)&3==0 and (registers['TCR_EL1']>>30)&3==2 and registers['SCTLR_EL1']&1 and registers['TTBR0_EL1'] and registers['TTBR1_EL1'],'Actual active native CPU4K hardware translation')
 require(d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'] and sink['protocol_responses_sent']==0 and 0<=sink['bytes_observed']<=65536 and not sink['errors'] and not sink['gpu_execution'] and not sink['system_device_published'],'Actual original crypto and bounded response-free console sink')
 console=d['native_console_globals'];require(all(console['_native_console_'+name]==0 for name in ('tx_requests','rx_requests','failures','tx_bytes','rx_bytes')),'No GPU host protocol traffic')
 broker=d['native_gpu_broker'];require(broker['stage']==3 and not broker['status'] and not broker['clients'] and not broker['requests'] and not broker['actual_cpu_contexts'] and not any(d['native_gpu_shared_events'].values()),'No private broker client, GPU operation or shared capability opened')
 require(provider['allocated']==provider['initialized']==provider['parent_match']==1 and provider['size']==736 and provider['object'] and provider['backend'] and provider['client_type']==kind and not provider['registered'] and not provider['start_returned'] and not provider['start_result'],'Actual unpublished own provider initialized; no successful provider start/publication')
 if kind:
  require(provider['stage']==4 and provider['status']==0xe00002c7-(1<<32) and provider['callback']==170 and not provider['released'] and not provider['factory_returned'] and not provider['factory_result'],'Real factory deliberately stops at unimplemented descriptor callback before returning a client')
  require(provider['instances_live']==provider['instances_before']+1 and provider['client_instances_live']==provider['client_instances_before']+1,'Actual own provider and actual original client each have a live instance')
  require(provider['client_instances_at_callback']==provider['client_instances_live'] and not provider['descriptor_refused'] and not provider['factory_out_client'],'Default capture never substitutes a descriptor refusal or returned client')
  frame=provider['frame'];capture=provider['factory_client_capture'];client=int(capture['address'],16);memory=bytes.fromhex(capture['bytes'])
  require(len(memory)==304 and int(capture['pointer'],16)==frame[1]==client+contract['shared_descriptor_out_offset'] and frame[0]==provider['object'] and frame[9]==int(contract['first_required_callback_caller_lr'],16),'Actual original client storage/output and original descriptor call site/LR')
  require(struct.unpack_from('<Q',memory)[0]==int(abi['vptr'],16) and struct.unpack_from('<Q',memory,248)[0]==provider['object'] and struct.unpack_from('<Q',memory,296)[0]==kind>>16,'Real original client class, provider and scalar high16 subtype, no substituted vtable/object')
  require(struct.unpack_from('<Q',memory,216)[0] and struct.unpack_from('<Q',memory,240)[0] and memory[264:296]==bytes(32),'Original custom initializer allocated real private task storage/lock; descriptor/mapping/output/device remain absent before missing callback')
  require((frame[10]>>14)&3==0 and (frame[10]>>30)&3==2 and frame[11]&1 and frame[12] and frame[13] and frame[14]%16==0,'Actual naked callback native4K translation registers and aligned SP')
 else:
  require(provider['stage']==3 and provider['status']==provider['factory_result']==0xe00002c2-(1<<32) and provider['factory_returned']==provider['released']==1 and not provider['callback'] and not any(provider['frame']) and not provider['attached'] and provider['instances_after']==provider['instances_before'] and provider['client_instances_live']==provider['client_instances_before'],'Original invalid type refuses with real kIOReturnBadArgument, creates no client and fully releases provider')
 rows.append(dict(open_type=kind,report_sha256=sha(path),required_slot=provider['callback'],client_started=False,factory_returned=bool(provider['factory_returned']),provider_released=bool(provider['released'])))
out=ROOT/'build/native-original-provider/client-factory-checkpoint.json'
out.write_text(json.dumps(dict(candidate_sha256=plan['candidate_sha256'],native_sha256=plan['native_sha256'],contract_sha256=sha(ROOT/'build/gpu-analysis/original-iogpu-client-contract.json'),observations=rows,actual_original_client_factory=True,actual_original_task_subtype_initialization=True,shared_descriptor_implemented=False,device_factory_implemented=False,original_client_started=False,provider_started=False,normal_device_discovery=False,original_desktop=False,adreno_execution=False,active_native_adreno_4k=False),indent=2)+'\n')
print('PASS: genuine original provider factory/custom task+subtype/client-start reach required descriptor slot170; high16 subtype and invalid-type cleanup controls')
print('The required descriptor is absent and the hook never returns; no successful client/provider startup, desktop or Adreno execution is claimed')
