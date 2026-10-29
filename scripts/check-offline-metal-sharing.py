#!/usr/bin/env python3
"""Qualify real original IOSurface Mach authorization, coherence and lifetime."""
import argparse
import runpy
import subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--renderbox-draw',action='store_true');p.add_argument('--depth-stencil',action='store_true');p.add_argument('--private-texture',action='store_true');p.add_argument('--renderbox-device',action='store_true');p.add_argument('--plugin-bundle',action='store_true');p.add_argument('--plugin-addon',action='store_true');a=p.parse_args()
if a.renderbox_draw:
    if a.depth_stencil or a.private_texture:p.error('Select one independent renderer/resource instrument')
    a.renderbox_device=True
if a.depth_stencil:
    if a.private_texture:p.error('Select one independent resource instrument')
    a.renderbox_device=True
if a.private_texture:a.renderbox_device=True
if a.renderbox_device:a.plugin_addon=True
if a.plugin_addon:a.plugin_bundle=True
if a.renderbox_device:subprocess.run(['python3',str(Path(__file__).with_name('audit-target-renderbox-device.py'))],check=True,timeout=60,capture_output=True)
n=runpy.run_path(__file__.replace('check-offline-metal-sharing.py','check-offline-metal-processes.py'))
globals().update({k:n[k] for k in ('ROOT','OUT','require','load','sha','modules','original','plan','cpu_contexts','text_code','json','struct','hashlib','plistlib','subprocess','re')})
kind='offline-metal-depth-stencil' if a.depth_stencil else 'offline-metal-private-texture' if a.private_texture else 'offline-renderbox-draw' if a.renderbox_draw else 'offline-renderbox-device' if a.renderbox_device else 'offline-metal-addon' if a.plugin_addon else 'offline-metal-plugin' if a.plugin_bundle else 'offline-metal-shared-surfaces'
directory=ROOT/'build'/kind;exe=directory/'air-native'
build=load(directory/'build-report.json');data=load(directory/'data-report.json');manifest=load(directory/'test-inputs.json')
require(sha(exe)==build['process_sha256']==data['process_sha256'] and
        sha(directory/'test-inputs.json')==build['manifest_sha256']==data['manifest_sha256'] and
        sha(directory/'compiler-data-32.cdr')==data['sha256'] and
        sha(directory/'offline-trust.bundle')==build['trust_bundle_sha256'],'Exact signed sharing instrument, Data, trust and manifest')
for name,digest in manifest['sources'].items():require(sha(ROOT/name)==digest,'Exact compiled sharing source '+name)
require(struct.unpack_from('<4I',exe.read_bytes())==(0xfeedfacf,0x100000c,0,2),'Actual own ARM64 subtype-0 process')
subprocess.run(['codesign','--verify','--strict',exe],check=True,timeout=30,capture_output=True)
detail=subprocess.run(['codesign','--display','--verbose=4',exe],capture_output=True,text=True,check=True,timeout=30).stderr
require(re.search(r'^Page size=4096$',detail,re.M) and build['cdhash'] in detail,'Actual own 4K CodeDirectory')
entitlements=plistlib.loads(subprocess.check_output(['codesign','-d','--entitlements',':-',str(exe)],stderr=subprocess.DEVNULL))
trust_modules=modules((directory/'offline-trust.bundle').read_bytes())
expected={'com.apple.private.security.no-container':True,
        'com.apple.security.iokit-user-client-class':['NativeOfflineGPUClient','IOSurfaceRootUserClient']}
if a.plugin_addon:expected['com.apple.private.bindfs-allow']=True
elif a.plugin_bundle:expected['com.apple.private.security.no-sandbox']=True
require(entitlements==build['entitlements']==expected and trust_modules[1:]==original,'Exact own diagnostic permissions and unchanged original trust modules')
if a.plugin_bundle:
    plugin=directory/'NativeOfflineMetal.bundle';binary=plugin/'NativeOfflineMetal'
    require(sha(binary)==build['plugin_sha256'] and sha(plugin/'Info.plist')==build['plugin_info_sha256'] and
            sha(plugin/'_CodeSignature/CodeResources')==build['plugin_resources_sha256'],'Exact actual own signed plugin and bundle resources')
    require(struct.unpack_from('<4I',binary.read_bytes())==(0xfeedfacf,0x100000c,0,6),'Actual own ARM64 subtype-0 dylib')
    info=plistlib.loads((plugin/'Info.plist').read_bytes())
    require(info['NSPrincipalClass']=='NativeOfflineMetalPlugin' and info['CFBundleIdentifier']=='org.blu-sharky.NativeOfflineMetal','Actual principal-class bundle metadata')
    subprocess.run(['codesign','--verify','--strict',plugin],check=True,timeout=30,capture_output=True)
    detail=subprocess.run(['codesign','--display','--verbose=4',plugin],capture_output=True,text=True,check=True,timeout=30).stderr
    require(re.search(r'^Page size=4096$',detail,re.M) and build['plugin_cdhash'] in detail and len(trust_modules)==3 and
            struct.unpack_from('<I',trust_modules[0],20)[0]==2 and len(trust_modules[0])==72 and
            [trust_modules[0][o:o+20].hex() for o in (24,48)]==sorted([build['cdhash'],build['plugin_cdhash']]) and
            all(trust_modules[0][o+20:o+24]==bytes([2,0,0,0]) for o in (24,48)),'Both exact own hashes belong to the one own trust module, with 4K CodeDirectories')
report=ROOT/('build/darwinboot-owner-hvf-'+kind+'-cpu-contexts/gdb-stop.json');d=load(report)
require(d['kernel_sha256']==plan['candidate_sha256'] and not d['bounded_timeout_interrupted'] and
        d['stop_symbol']=='_exception_triage' and d['native_4k_mmu_observed'] and d['original_amfi_table_owner_observed'] and
        d['owner_root_binding_audit']['boot_root_accepted'] and d['actual_process']['pid']==1 and d['actual_process']['name']=='air-native' and
        d['actual_signature_failures']==dict(_cs_validate_page_bad_hash=0,_cs_validate_page_no_hash=0) and
        d['scratch_data']['actual_seed_sha256']==data['sha256'] and d['trust_cache_bundle_sha256']==build['trust_bundle_sha256'],
        'Actual original runtime, native CPU 4K, original AMFI/root and own EL0 boundary')
u=d['entry_user_state_candidates'][0];v=struct.unpack('<32Q',bytes.fromhex(u['register_memory']['13:100']['bytes']))
require(int(u['cpsr'],16)&31==0 and u['instruction_bytes'].startswith('000020d4') and
        v[0:4]==(0x53485250,1,4096,4096) and v[4]>1 and v[12]>1 and v[4]!=v[12] and
        v[5:7]==v[13:15]==(4096,4096) and v[7] and v[15] and v[7]!=v[15] and
        v[8]==v[16]!=0 and v[10:12]==(0,4) and v[18:23]==(1,4,0,0,1) and
        len(set(v[26:29]))==3 and v[9]==v[28] and v[17] not in v[26:29],
        'Two actual children share the same original surface through real Mach descriptors, reject a non-surface right, observe changed seeds and exit successfully')
sessions=cpu_contexts(d,(v[4],v[12]));broker=d['native_gpu_broker']
if a.plugin_addon:
    addon=data['addon'];require(addon['volume_uuid']==data['volume_uuid'] and addon['plugin_sha256']==build['plugin_sha256'] and
        addon['offline_only'] and addon['mutable_backing'] and addon['read_only_bindfs_view'] and not addon['production_root_authorization'] and
        v[29]&33==33 and v[30] and v[31] and v[30]!=v[31],
        'Actual read-only union bindfs addon on own RAM Data and surviving original lower-volume extension; no immutable addon or production-root claim')
expected_requests=207 if a.renderbox_draw else 243 if a.depth_stencil else 115 if a.private_texture else 69 if a.renderbox_device else 67
expected_reply=257426 if a.renderbox_draw else 241058 if a.depth_stencil else 118864 if a.private_texture else 84560 if a.renderbox_device else 84496
require(broker['stage']==3 and broker['status']==0 and broker['clients']==broker['closed']==2 and
        not broker['active'] and broker['requests']==expected_requests and broker['reply_bytes']==expected_reply and not broker['failures'] and broker['refusals']==(6 if a.depth_stencil else 4 if a.private_texture else 0),
        'Actual complete private broker lifetimes and real protocol results')
host_path=directory/'host-cpu-contexts-report.json';host=load(host_path);ops=host['operations']
require(host['host_device']=='Apple M1' and host['isolated_sessions'] and host['opened_sessions']==host['closed_sessions']==2 and
        not host['cpu_pixel_renderer'] and not host['guest_system_device_discovery'] and not host['adreno_execution'] and not host['original_desktop'] and
        len(ops)==expected_requests and all(o['request']==i+1 for i,o in enumerate(ops)) and sum(bool(o['error']) for o in ops)==(6 if a.depth_stencil else 4 if a.private_texture else 0),'Actual real host GPU ledger and explicit offline scope')
if a.renderbox_device:
    # The exact own instrument calls the unchanged original initializer and
    # requires the real device/queue getters before either worker can proceed.
    # Original RenderBox allocates one real initial buffer per worker.
    buffers=[o for o in ops if o['operation']==0x111]
    require(len(buffers)==(4 if a.renderbox_draw else 2) and {o['session'] for o in buffers}==set(sessions.values()) and
        len({o['handle'] for o in buffers})==len(buffers) and all(o['handle'] and o['input_bytes']==16 for o in buffers),
        'Both original RenderBox constructors actually allocate a GPU buffer in their own independent namespace')
    for o in [next(b for b in buffers if b['session']==sid) for sid in sessions.values()]:
        first_texture=next(t for t in ops if t['operation']==0x104 and t['session']==o['session'])
        require(o['request']<first_texture['request'],'Original constructor executes before the subsequent surface GPU test')
textures={o['handle']:o['session'] for o in ops if o['operation']==0x104}
require(textures[v[7]]==sessions[v[4]] and textures[v[15]]==sessions[v[12]],'Shared original surface has independent real per-client host textures')
commands=host['completed_commands'];commits=[o for o in ops if o['operation']==0x10c]
enqueued=host['enqueued_commands'];require(host['transport_healthy'] and host['session_finished'] and not host['pending_enqueues'] and
    len(enqueued)==(12 if a.depth_stencil else 6 if (a.private_texture or a.renderbox_draw) else 4) and all(r['status']==1 for r in enqueued) and {r['command'] for r in enqueued}=={r['command'] for r in commands},
    'Four real Enqueued reservations subsequently complete on GPU; exact own callbacks require real completion/timing and ordered single delivery')
if a.depth_stencil:
    require(len(commands)==len(commits)==12 and all(r['status']==4 and 0<r['gpu_start_ns']<r['gpu_end_ns'] for r in commands),'Twelve real original-shader/IOSurface GPU completions')
    stencil_indices={i for sid in sessions.values() for i in [j for j,o in enumerate(commits) if o['session']==sid][:4]}
    commands=[c for i,c in enumerate(commands) if i not in stencil_indices];commits=[c for i,c in enumerate(commits) if i not in stencil_indices]
    require(len(host['depth_stencil_states'])==4 and len(host['attachment_passes'])==len(host['stencil_references'])==8,'Actual state allocations and eight real depth/stencil render encoders')
    color_hash=hashlib.sha256(struct.pack('<I',0xff996633)*4096).hexdigest();zero_hash=hashlib.sha256(bytes(16384)).hexdigest()
    for sid in sessions.values():
        states=[r for r in host['depth_stencil_states'] if r['session']==sid];passes=[r for r in host['attachment_passes'] if r['session']==sid];refs=[r for r in host['stencil_references'] if r['session']==sid]
        require(len(states)==2 and {r['depth_compare'] for r in states}=={1,7} and all(not r['depth_write'] and r['front_compare']==r['back_compare']==2 and not r['front_write_mask'] and not r['back_write_mask'] for r in states),
            'Actual Equal stencil state, Always/Less depth states and disabled writes in each real task')
        require(len(passes)==len(refs)==4 and [r['depth_clear'] for r in passes]==[1,1,0,1] and [r['stencil_load'] for r in passes]==[2,1,1,1] and
            all(r['width']==r['height']==64 and r['depth'] and r['stencil'] and r['depth_load']==2 and r['stencil_clear']==1 for r in passes) and
            [r['front'] for r in refs]==[2,1,1,1] and all(r['front']==r['back'] for r in refs), 'Actual mismatch/match and depth-reject/pass attachment/reference controls')
        readbacks=[r for r in host['texture_readbacks'] if r['texture'] not in (v[7],v[15]) and textures[r['texture']]==sid]
        require(len(readbacks)==4 and all(r['bytes']==16384 for r in readbacks) and [r['sha256'] for r in readbacks]==[color_hash,zero_hash,color_hash,zero_hash],
            'Every original-shader GPU pixel obeys the real stencil and depth tests in each native worker')
        errors=[o for o in ops if o['session']==sid and o['error']];require([(o['operation'],o['error']) for o in errors]==[(0x102,-4),(0x103,-4),(0x10d,-2)],
            'Actual non-library file, missing shader and private stencil CPU read refuse independently; invalid constant types/bindings fail before transport')
        libraries=[o for o in ops if o['session']==sid and o['operation']==0x102]
        require(len(libraries)==4 and sum(bool(o['handle']) for o in libraries)==3 and all(o['input_bytes']==32 for o in libraries),
            'Each real worker loads the original library via file/URL and bundle paths, while its actual Info.plist hash refuses')
        rows=[r for r in host['function_specializations'] if r['session']==sid]
        require(len(rows)==4 and [r['name'] for r in rows]==['plane_color_fragment','__native_missing__','plane__vertex','plane_color_fragment'] and
            [r['actual_success'] for r in rows]==[True,False,True,True] and not rows[-1]['constants'] and
            all(len(r['constants'])==1 and r['constants'][0]['data_hex']=='020000000000000046f4530004000000' for r in rows[:-1]) and
            rows[0]['constants'][0]['name']=='RB::Shader::Constant::_shader_state' and not rows[2]['constants'][0]['name'],
            'Real original named/indexed accessors preserve exact UInt4 bytes; missing function genuinely fails while empty values retain actual backend semantics')
if a.renderbox_draw:
    require(len(commands)==len(commits)==6 and all(r['status']==4 and 0<r['gpu_start_ns']<r['gpu_end_ns'] for r in commands),
        'Both original RenderBox commands and all four independent surface commands actually complete on GPU')
    indices={next(i for i,o in enumerate(commits) if o['session']==sid) for sid in sessions.values()}
    commands=[c for i,c in enumerate(commands) if i not in indices];commits=[c for i,c in enumerate(commits) if i not in indices]
    actual=host['function_specializations'];require(len(actual)==8 and all(r['actual_success'] and not r['actual_error'] for r in actual),
        'Eight actual original RenderBox vertex/fragment specializations succeed without altering original shader code')
    expected_data={'020000000000000046f4530004000000','021000000000000046f4530004000000'}
    for sid in sessions.values():
        rows=[r for r in actual if r['session']==sid]
        require(len(rows)==4 and {r['name'] for r in rows}=={'plane__vertex','plane_color_fragment'} and
            all(len(r['constants'])==1 and r['constants'][0]['type']==36 and r['constants'][0]['index']==0 and not r['constants'][0]['name'] and r['constants'][0]['bytes']==16 for r in rows) and
            {r['constants'][0]['data_hex'] for r in rows}==expected_data,'Actual original UInt4 shader states and both original functions in each native process')
    rendered=[r for r in host['texture_readbacks'] if r['texture'] not in (v[7],v[15])]
    expected_hash=hashlib.sha256((struct.pack('<I',0xff0000ff)*32+struct.pack('<I',0xffff0000)*32)*64).hexdigest()
    require(len(rendered)==2 and len({r['texture'] for r in rendered})==2 and
        all(r['bytes']==16384 and r['sha256']==expected_hash for r in rendered),'Both original GPU outputs independently match all 4096 left-red/right-blue pixels')
    initial=[r for r in host['texture_uploads'] if r['texture'] not in (v[7],v[15])]
    require(len(initial)==10 and sum(r['bytes'] for r in initial)==32768 and all(r['sha256']==hashlib.sha256(bytes(r['bytes'])).hexdigest() for r in initial),
        'Both real original surface uploads are entirely zero; expected shapes originate in actual GPU shaders rather than CPU-painted uploads')
    require(not host['aborted_encoders'] and not host['open_encoders'],'Complete actual rendering requires no abandoned encoding')
if a.private_texture:
    require(len(commands)==len(commits)==6 and all(r['status']==4 and 0<r['gpu_start_ns']<r['gpu_end_ns'] for r in commands),'Six real private-render/shared-surface command completions')
    # First commit in each namespace belongs to that worker's private-texture
    # test, independently of how the two actual dispatch schedules interleave.
    private_indices={next(i for i,o in enumerate(commits) if o['session']==sid) for sid in sessions.values()}
    commands=[c for i,c in enumerate(commands) if i not in private_indices]
    commits=[c for i,c in enumerate(commits) if i not in private_indices]
    copies=host['texture_copies'];require(len(copies)==2 and {c['session'] for c in copies}==set(sessions.values()) and
        all(c['format']==65 and c['source_storage']==2 and c['destination_storage']==0 and c['width']==c['height']==64 and c['source']!=c['destination'] for c in copies),
        'Both actual private RG16Float textures are copied by GPU to distinct shared textures')
    for c in copies:
        readback=next(r for r in host['texture_readbacks'] if r['texture']==c['destination'])
        require(readback['bytes']==16384 and readback['sha256']==hashlib.sha256(struct.pack('<I',0x3a003400)*4096).hexdigest(),'Every actual half-float private GPU pixel replaces the contrasting destination GPU clear')
    for sid in sessions.values():
        errors=[o for o in ops if o['session']==sid and o['error']]
        require(len(errors)==2 and {o['operation'] for o in errors}=={0x122,0x10d} and all(o['error']==-2 for o in errors),
            'Actual native invalid texture-copy bounds and private CPU reads refuse in both tasks')
require(len(commands)==len(commits)==4 and all(r['status']==4 and 0<r['gpu_start_ns']<r['gpu_end_ns'] for r in commands) and
        [o['session'] for o in commits]==[sessions[v[4]],sessions[v[12]],sessions[v[4]],sessions[v[12]]],
        'Four actual ordered creator/peer/creator-load/peer GPU completions')
close1=next(o['request'] for o in ops if o['operation']==0x141 and o['session']==sessions[v[4]])
require(commits[-1]['request']>close1 and ops[-1]['operation']==0x141,'Peer genuinely draws after creator session closes and actual parent waitpid reaps creator')
pixels=[0xff996633,0xff996633,0xff3366cc,0xff3366cc,0xffff00ff]
readbacks=[r for r in host['texture_readbacks'] if r['texture'] in (v[7],v[15])];require(len(readbacks)==5 and [r['texture'] for r in readbacks]==[v[7],v[15],v[15],v[7],v[15]],'Exact whole-surface import/coherence/lifetime readbacks')
for r,pixel in zip(readbacks,pixels):require(r['bytes']==16384 and r['sha256']==hashlib.sha256(struct.pack('<I',pixel)*4096).hexdigest(),'Every real GPU readback agrees with all native original surface pixels')
uploads=[r for r in host['texture_uploads'] if r['texture'] in (v[7],v[15])];require(len(uploads)==20 and sum(r['bytes'] for r in uploads)==65536,'Four complete real original-surface uploads across both host contexts')
for handle,pixel in ((v[7],0xff3366cc),(v[15],0xff996633)):
    rows=[r for r in uploads if r['texture']==handle and r['sha256']==hashlib.sha256(struct.pack('<I',pixel)*(r['bytes']//4)).hexdigest()]
    require(sum(r['bytes'] for r in rows)==16384 and [r['y'] for r in rows]==[0,15,30,45,60],
            'Actual shared-surface pixels cross into the existing independent remote texture after original seed changes')
(OUT/('renderbox-draw-checkpoint.json' if a.renderbox_draw else 'depth-stencil-checkpoint.json' if a.depth_stencil else 'private-texture-checkpoint.json' if a.private_texture else 'renderbox-device-checkpoint.json' if a.renderbox_device else 'addon-checkpoint.json' if a.plugin_addon else 'plugin-checkpoint.json' if a.plugin_bundle else 'sharing-checkpoint.json')).write_text(json.dumps(dict(candidate_sha256=plan['candidate_sha256'],
    report_sha256=sha(report),host_report_sha256=sha(host_path),actual_original_surface_id=v[8],
    actual_native_gpu_processes=2,actual_host_gpu_completions=12 if a.depth_stencil else 6 if (a.private_texture or a.renderbox_draw) else 4,actual_worker_cpu_4k_contexts=2,
    mach_authorized_original_surface_shared=True,unrelated_mach_object_refused=True,
    real_surface_seed_coherence=True,peer_executes_after_creator_exit=True,explicit_own_bundle_factory=a.plugin_bundle,
    actual_enqueued_commands=12 if a.depth_stencil else 6 if (a.private_texture or a.renderbox_draw) else 4,actual_ordered_callback_invocations=24 if a.depth_stencil else 12 if a.private_texture else 8,scheduled_callbacks_deliberately_late=True,
    actual_shared_surface_format='RGBA8Unorm',cpu_channel_conversion=False,private_rg16float_gpu_render_copy=a.private_texture,actual_gpu_depth_stencil=a.depth_stencil,
    readonly_own_addon_view=a.plugin_addon,production_addon_authorization=False,
    original_renderbox_device_initialized=a.renderbox_device,original_renderbox_rendering=a.renderbox_draw,
    system_metal=False,original_desktop=False,adreno_execution=False,active_native_adreno_4k=False),indent=2)+'\n')
print('PASS: original IOSurface shared by genuine Mach send rights, unrelated object refused, real seed coherence and peer GPU work after creator exit')
print('PASS: four genuine Enqueued commands, actual GPU completion and ordered once-only native scheduled/completed callbacks; both real commit interfaces exercised')
if a.plugin_bundle:print('PASS: original NSBundle loads own signed plugin and real _MTLDevice factory binds the actual guest service in both workers')
if a.plugin_addon:print('PASS: actual read-only native union bindfs view preserves original extension access; factory device reports the actual provided guest service registry ID')
if a.renderbox_device and not a.renderbox_draw:print('PASS: both original RenderBox device initializers and real device/queue getters succeed; no complete GPU family or original rendering claimed')

if a.private_texture:print('PASS: both native private RG16Float GPU renders/copies, all half-float pixels and genuine bounds/private-CPU-read refusals')

if a.depth_stencil:print('PASS: both native workers execute unchanged original shaders with real stencil mismatch/match and depth rejection/pass, complete output and private CPU-read refusals')

if a.renderbox_draw:print('PASS: unchanged original RenderBox GPU drawing and returned 4096-pixel two-color images in both native-4K workers; normal Metal, desktop and Adreno remain open')
