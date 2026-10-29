#!/usr/bin/env python3
"""Record actual original Sandbox scoped IOKit authorization, including real denial."""
import hashlib,json,re,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'kits/XnuPrelink'))
from native_prelink import macho,backed_offset
def require(value,why):
 if not value:raise SystemExit(why)
def load(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def modules(raw):
 n=struct.unpack_from('<I',raw)[0];starts=struct.unpack_from('<'+'I'*n,raw,4)
 return [raw[a:b] for a,b in zip(starts,(*starts[1:],len(raw)))]
folder=ROOT/'build/offline-sandbox-extension';fixture=ROOT/'build/darwinboot-owner-hvf-offline-sandbox-extension'
d=load(fixture/'gdb-stop.json')
build=load(folder/'build-report.json');data=load(folder/'data-report.json');manifest=load(folder/'test-inputs.json')
base=ROOT/'build/xnu-prelink/native-owner-accelerator-abi-candidate';plan=load(base.with_suffix('.json'));raw=base.with_suffix('.macho').read_bytes();segments=macho(raw)['segments']
require(sha(base.with_suffix('.macho'))==plan['candidate_sha256']==d['kernel_sha256'],'Actual immutable candidate identity')
old=load(ROOT/'build/xnu-prelink/native-owner-offline-gpu-broker-cpu-candidate.json')
require(plan['components']==old['components'] and plan['original_executable_sha256']==old['original_executable_sha256'] and plan['early_security_initializers']==old['early_security_initializers'],'All 29 original executable hashes and security initialization preserved')
for module,digest in plan['original_executable_sha256'].items():
 e=next(e for e in plan['extents'] if e['module']==module and e['segment']=='__TEXT_EXEC');at=backed_offset(segments,e['va'],e['size'],len(raw))
 require(hashlib.sha256(raw[at:at+e['size']]).hexdigest()==digest,'Actual whole original executable identity: '+module)
for name,digest in manifest['sources'].items():require(sha(ROOT/name)==digest,'Exact compiled frontend/instrument source: '+name)
require(sha(folder/'air-native')==build['process_sha256']==data['process_sha256'] and sha(folder/'compiler-data-32.cdr')==data['sha256'] and
 sha(folder/'test-inputs.json')==build['manifest_sha256']==data['manifest_sha256'] and sha(folder/'offline-trust.bundle')==build['trust_bundle_sha256'],'Exact signed own process, Data, trust and source manifest')
require(struct.unpack_from('<4I',(folder/'air-native').read_bytes())==(0xfeedfacf,0x100000c,0,2),'Actual ordinary ARM64 process')
for signed in (folder/'air-native',folder/'sandbox-consumer'):
 subprocess.run(['codesign','--verify','--strict',signed],check=True,capture_output=True,timeout=30)
 detail=subprocess.run(['codesign','--display','--verbose=4',signed],check=True,capture_output=True,text=True,timeout=30).stderr
 require(re.search(r'^Page size=4096$',detail,re.M),'Actual own 4K CodeDirectory')
require(modules((folder/'offline-trust.bundle').read_bytes())[1:]==modules((ROOT/'build/original-static-system-trust/original-static-system.bundle').read_bytes()),'Both complete original trust modules unchanged')
require(not d['bounded_timeout_interrupted'] and d['stop_symbol']=='_exception_triage' and d['actual_process']['pid']==1 and d['actual_process']['name']=='air-native' and
 d['native_4k_mmu_observed'] and d['original_amfi_table_owner_observed'] and d['owner_root_binding_audit']['boot_root_accepted'] and
 d['owner_root_binding_audit']['_native_owner_root_apple_autherr']==80 and d['actual_signature_failures']==dict(_cs_validate_page_bad_hash=0,_cs_validate_page_no_hash=0) and
 d['scratch_data']['actual_seed_sha256']==data['sha256'] and d['trust_cache_bundle_sha256']==build['trust_bundle_sha256'],'Actual original root/AMFI/inputs and native CPU 4K at real EL0 boundary')
u=d['entry_user_state_candidates'][0];v=struct.unpack('<32Q',bytes.fromhex(u['register_memory']['13:100']['bytes']))
require(not int(u['cpsr'],16)&31 and u['instruction_bytes'].startswith('000020d4') and v[:6]==(0x5342494f,1,4096,4096,0,0),'Actual own issuer EL0 checkpoint and native page-size ABI')
require(v[6:9]==(0,3,0) and v[25:28]==(0,0,0) and v[28]==v[29] and v[28]>1 and v[30]==0,'Actual entitled issuer open, both token issuances, real separate consumer and normal exit; no consumer opens succeeded')
# Child fields 6..21 are copied verbatim to parent fields 9..24.
require(v[9] and all(v[i]==0xe00002e2 for i in (10,12,14,17,19)) and all(v[i]==0 for i in (11,13,16,18)),'Actual unentitled consumer stays NotPermitted before, during both real consumed scopes and after each successful release')
require(v[23]-d['actual_process']['shared_region_slide']==0x1dd55bce8 and v[24]-d['actual_process']['shared_region_slide']==0x1dd55b9ac,'Exact unchanged original consume/release implementations, not local replacements')
require(d['entry_register_selection']==dict(index=0,expected='0x6',observed='0x6') and d['skipped_target_hits']==3,'Read-only observer selects actual EXC_BREAKPOINT after three earlier exception entries; target exception delivery is unmodified')
b=d['native_gpu_broker'];require(b['stage']==0 and b['clients']==b['requests']==b['closed']==b['active']==0,'No GPU broker publication, protocol traffic or fabricated rendering in this authorization observation')
require(all(d['kernel_page_globals'][k]==x for k,x in [('_PAGE_SHIFT_CONST',12),('_page_shift',12),('_page_shift_user32',12),('_page_size',4096)]) and int(d['system_registers']['TCR_EL1'],16)==0x22a51a251a and int(d['system_registers']['SCTLR_EL1'],16)&1,'Active native CPU registers and full native userspace 4K globals')
consumer=folder/'sandbox-consumer';require(sha(consumer)==build['consumer_sha256'],'Exact independently signed consumer input')
consumer_entitlements=subprocess.check_output(['codesign','-d','--entitlements',':-',consumer],stderr=subprocess.DEVNULL)
issuer_entitlements=subprocess.check_output(['codesign','-d','--entitlements',':-',folder/'air-native'],stderr=subprocess.DEVNULL)
import plistlib
require(plistlib.loads(consumer_entitlements)=={'com.apple.private.security.no-container':True} and plistlib.loads(issuer_entitlements)==build['entitlements'] and build['entitlements']=={'com.apple.private.security.no-container':True,'com.apple.security.iokit-user-client-class':['NativeOfflineGPUClient','IOSurfaceRootUserClient']},'Consumer has no IOKit allowlist; issuer retains only exact own diagnostic scopes')
subprocess.run(['codesign','--verify','--strict',consumer],check=True,capture_output=True,timeout=30)
code=[]
for file in (folder/'air-native',consumer):
 binary=file.read_bytes();section=next(sec for seg in macho(binary)['segments'] for sec in seg['sections'] if seg['name']=='__TEXT' and sec['name']=='__text');code.append(binary[section['fileoff']:section['fileoff']+section['size']])
require(code[0]==code[1],'Actual issuer and consumer machine instructions identical; only their signatures/scopes differ')
(folder/'checkpoint.json').write_text(json.dumps(dict(candidate_sha256=plan['candidate_sha256'],issuer_sha256=build['process_sha256'],consumer_sha256=build['consumer_sha256'],qemu_report_sha256=sha(fixture/'gdb-stop.json'),same_machine_instructions=True,entitled_issuer_open=True,real_tokens_issued=2,real_consume_release_pairs=2,consumer_opens_succeeded=0,consumer_status='NotPermitted',authorization_route_qualified=False,original_apps_modified=False,original_sandbox_unchanged=True,original_desktop=False,adreno_execution=False),indent=2)+'\n')
print('PASS observation: entitled issuer opens; two genuine Sandbox tokens consume/release, but consumer remains NotPermitted')
print('NEGATIVE authorization result: scoped tokens do not grant this target profile IOKit access; no system-client integration qualified')
