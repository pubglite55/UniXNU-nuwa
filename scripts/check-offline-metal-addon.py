#!/usr/bin/env python3
"""Verify actual own bundle factory, readonly view and original signature refusal."""
import runpy
import sys
from pathlib import Path
script=Path(__file__).with_name('check-offline-metal-sharing.py')
saved=sys.argv;sys.argv=[str(script),'--plugin-addon']
try:n=runpy.run_path(str(script))
finally:sys.argv=saved
globals().update({k:n[k] for k in ('ROOT','OUT','require','load','sha','modules','original','plan','text_code','json','struct','plistlib','subprocess','re')})
positive=n['directory'];positive_build=n['build'];positive_manifest=n['manifest']
observations=[]
for control in ('without-mount-permission','tampered-code'):
    directory=ROOT/('build/offline-metal-addon-'+control);build=load(directory/'build-report.json');data=load(directory/'data-report.json')
    require(sha(directory/'air-native')==build['process_sha256']==data['process_sha256'] and
            sha(directory/'test-inputs.json')==build['manifest_sha256']==data['manifest_sha256'] and
            load(directory/'test-inputs.json')==positive_manifest and sha(directory/'compiler-data-32.cdr')==data['sha256'] and
            sha(directory/'offline-trust.bundle')==build['trust_bundle_sha256'],'Exact own control process, sources, Data and explicit trust')
    require(text_code(directory/'air-native')==text_code(positive/'air-native') and
            text_code(directory/'NativeOfflineMetal.bundle/NativeOfflineMetal')==text_code(positive/'NativeOfflineMetal.bundle/NativeOfflineMetal') and
            sha(directory/'NativeOfflineMetal.bundle/NativeOfflineMetal')==build['plugin_sha256'],
            'Every control executes identical own machine instructions and uses the same original own signed plugin')
    subprocess.run(['codesign','--verify','--strict',directory/'air-native'],check=True,timeout=30,capture_output=True)
    detail=subprocess.run(['codesign','--display','--verbose=4',directory/'air-native'],check=True,capture_output=True,text=True,timeout=30).stderr
    require(re.search(r'^Page size=4096$',detail,re.M) and build['cdhash'] in detail,'Actual own control 4K CodeDirectory')
    entitlements=plistlib.loads(subprocess.check_output(['codesign','-d','--entitlements',':-',str(directory/'air-native')],stderr=subprocess.DEVNULL))
    expected=dict(n['expected'])
    if control=='without-mount-permission':expected.pop('com.apple.private.bindfs-allow')
    require(entitlements==build['entitlements']==expected,'Only the requested own mount permission differs')
    trust=modules((directory/'offline-trust.bundle').read_bytes())
    require(len(trust)==3 and trust[1:]==original and len(trust[0])==72 and struct.unpack_from('<I',trust[0],20)[0]==2 and
            [trust[0][o:o+20].hex() for o in (24,48)]==sorted([build['cdhash'],build['plugin_cdhash']]),'Both exact own hashes and unchanged original trust modules')
    report=ROOT/('build/darwinboot-owner-hvf-offline-metal-addon-'+control+'-cpu-contexts/gdb-stop.json');d=load(report);observations.append(report)
    require(d['kernel_sha256']==plan['candidate_sha256'] and not d['bounded_timeout_interrupted'] and d['native_4k_mmu_observed'] and
            d['original_amfi_table_owner_observed'] and d['owner_root_binding_audit']['boot_root_accepted'] and
            d['scratch_data']['actual_seed_sha256']==data['sha256'] and d['trust_cache_bundle_sha256']==build['trust_bundle_sha256'] and
            not d['native_gpu_broker']['clients'] and not d['native_gpu_broker']['requests'] and not d['native_gpu_broker']['actual_cpu_contexts'],
            'Real native CPU 4K, original AMFI/root, exact negative inputs and zero GPU access')
    if control=='without-mount-permission':
        u=d['entry_user_state_candidates'][0];v=struct.unpack('<32Q',bytes.fromhex(u['register_memory']['13:100']['bytes']))
        require(d['stop_symbol']=='_exception_triage' and d['actual_process']['pid']==1 and
                int(u['cpsr'],16)&31==0 and u['instruction_bytes'].startswith('000020d4') and
                v[:4]==(0x53484641,1,4096,4096) and v[22:24]==(281,1) and v[29:32]==(0,0,0) and
                d['actual_signature_failures']==dict(_cs_validate_page_bad_hash=0,_cs_validate_page_no_hash=0),
                'Actual original bindfs entitlement check refuses with EPERM before any view or GPU client')
    else:
        require(d['stop_symbol']=='_cs_invalid_page' and d['actual_process']['pid']>1 and d['actual_process']['name']=='air-native' and
                d['actual_signature_failures']['_cs_validate_page_bad_hash']==1 and not d['actual_signature_failures']['_cs_validate_page_no_hash'],
                'Actual worker code fault rejects a bad signed code page, without missing-signature fallback')
        mount=directory/'inspect-mount';mount.mkdir(exist_ok=True)
        attached=plistlib.loads(subprocess.check_output(['hdiutil','attach',str(directory/'compiler-data-32.cdr'),'-readonly','-nobrowse','-mountpoint',str(mount),'-plist'],timeout=30))
        try:
            target=mount/'tmp/native-metal-addons/NativeOfflineMetal.bundle/NativeOfflineMetal'
            pristine=(directory/'NativeOfflineMetal.bundle/NativeOfflineMetal').read_bytes();broken=target.read_bytes();offset=data['addon']['tamper_file_offset']
            require(len(pristine)==len(broken) and [i for i,(a,b) in enumerate(zip(pristine,broken)) if a!=b]==[offset] and
                    pristine[offset]^broken[offset]==1 and sha(target)==data['addon']['actual_plugin_sha256'] and
                    data['addon']['original_signature_retained'],'Actual staged negative file differs by exactly the recorded own instruction byte')
            detail=subprocess.run(['codesign','--display','--verbose=4',target],capture_output=True,text=True,check=True,timeout=30).stderr
            invalid=subprocess.run(['codesign','--verify','--strict',target],capture_output=True,timeout=30)
            require(build['plugin_cdhash'] in detail and invalid.returncode!=0,'Actual unchanged own CodeDirectory has trusted hash but its changed code fails host verification too')
        finally:subprocess.run(['hdiutil','detach',attached['system-entities'][0]['dev-entry']],check=True,timeout=30,capture_output=True)
(OUT/'addon-controls-checkpoint.json').write_text(json.dumps(dict(candidate_sha256=plan['candidate_sha256'],
    positive_checkpoint_sha256=sha(OUT/'addon-checkpoint.json'),control_report_sha256=[sha(p) for p in observations],
    mount_permission_refused=True,tampered_own_signed_code_refused=True,original_signature_checks_preserved=True,
    readonly_own_addon_view=True,mutable_test_backing=True,production_addon_authorization=False,
    system_metal=False,original_desktop=False,adreno_execution=False,active_native_adreno_4k=False),indent=2)+'\n')
print('PASS: identical own code loses bindfs access without its signed permission; one changed own plugin instruction faults in real code-signature validation before GPU access')
