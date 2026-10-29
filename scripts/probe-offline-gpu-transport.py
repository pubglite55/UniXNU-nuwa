#!/usr/bin/env python3
"""Bounded genuine native iOS17 -> VirtIO -> host Metal GPU round-trip."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'build/offline-gpu-transport'
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--broker-processes',action='store_true',help='Two actual original-userland GPU processes through the private kernel broker')
p.add_argument('--broker-spawn-observe',choices=['posix_spawn','fork1','exec_activate_image','exec_mach_imgact','mac_vnode_check_exec'],help='Read a genuine original spawn boundary and return without claiming GPU completion')
p.add_argument('--broker-map-observe',action='store_true',help='Read actual executable mmap MAC return and registered hooks for the own plugin')
p.add_argument('--broker-map-policy',choices=['mac','AMFI','Sandbox'],default='mac',help='Read a genuine registered mapping hook, without changing policy')
p.add_argument('--legacy-swap-wait',action='store_true',help='Read actual original SwapWaitWithTimeout status after first GPU frame')
p.add_argument('--legacy-queue-retirement',action='store_true',help='Use original queue completion only after actual first-frame scanout transfer')
p.add_argument('--legacy-swap',action='store_true',help='Submit real GPU IOSurface through original framebuffer transaction')
p.add_argument('--legacy-queue-transfer',action='store_true',help='Transfer one completed actual GPU surface from the real pending queue without retiring it')
p.add_argument('--legacy-gop-validation',action='store_true',help='Qualify the actual one-full-frame IOSurface validator')
p.add_argument('--legacy-logical-pm',action='store_true',help='Use genuine IOKit logical scanout scheduling, without panel power claims')
p.add_argument('--legacy-swap-submit',action='store_true',help='Observe unchanged original kernel swap_submit entry and real marshaled packet')
p.add_argument('--legacy-swap-decision',action='store_true',help='Observe original validated-swap submission gate, without changing its state')
p.add_argument('--legacy-swap-validate',action='store_true',help='Observe original mandatory backend validation return and actual IOSurface')
p.add_argument('--legacy-swap-kick',action='store_true',help='Observe original queue-kick entry only after actual resource validation')
p.add_argument('--iosurface',action='store_true',help='Exercise real original IOSurface-backed Metal textures')
p.add_argument('--bgra',action='store_true',help='Exercise actual BGRA IOSurface uploads, GPU drawing and readback')
p.add_argument('--present',action='store_true',help='Transfer actual display-size GPU output to genuine GOP scanout')
p.add_argument('--resources',action='store_true',help='Use real GPU buffers, blit, original buffer-driven vertex and indexed draws')
p.add_argument('--compose',action='store_true',help='Use actual GPU texture reads, clipping and blend state for layer composition')
p.add_argument('--metal-api',action='store_true',help='Run the partial native Metal object/command frontend')
p.add_argument('--case',choices=['positive','missing-device','default-off','validation-disabled','transfer-disabled','retirement-disabled','without-container','without-client'],default='positive')
p.add_argument('--depth-stencil',action='store_true');p.add_argument('--private-texture',action='store_true');p.add_argument('--renderbox-draw',action='store_true');p.add_argument('--renderbox-device',action='store_true');p.add_argument('--plugin-control',choices=['full','without-mount-permission','tampered-code'],default='full');p.add_argument('--plugin-addon',action='store_true');p.add_argument('--plugin-bundle',action='store_true');p.add_argument('--shared-surfaces',action='store_true',help='Pass actual IOSurface Mach rights between two GPU processes')
a=p.parse_args()
if a.depth_stencil:
    if a.private_texture or a.renderbox_draw:p.error('Select one independent resource or renderer instrument')
    a.renderbox_device=True
if a.private_texture:
    if a.renderbox_draw:p.error('Select one independent resource or original renderer instrument')
    a.renderbox_device=True
if a.renderbox_draw:a.renderbox_device=True
if a.renderbox_device:
    if a.plugin_control!='full':p.error('RenderBox device observation is a separate instrument')
    a.plugin_addon=True
if a.plugin_control!='full':a.plugin_addon=True
if a.plugin_addon:a.plugin_bundle=True
if a.plugin_bundle:a.shared_surfaces=True
if a.broker_map_policy!='mac':a.broker_map_observe=True
if a.shared_surfaces:a.broker_processes=True
if a.shared_surfaces and a.case!='positive':p.error('Use --broker-processes for the independently qualified broker controls')
if a.broker_map_observe and (not a.plugin_bundle or a.broker_spawn_observe):p.error('Select only the explicit own plugin mmap observer')
if a.broker_processes:
    if a.legacy_swap or a.legacy_swap_wait or a.compose or a.resources or a.present or a.case not in ('positive','missing-device','default-off','without-container','without-client'):p.error('Select one GPU process instrument or its missing-device/default-off control')
    a.metal_api=True;a.bgra=True
if a.case in ('without-container','without-client') and not a.broker_processes:p.error('Permission controls require the private GPU instrument')
if a.broker_spawn_observe and (not a.broker_processes or a.case!='positive'):p.error('Spawn observation requires the enabled private GPU instrument')
if a.legacy_swap_wait:a.legacy_swap=True
if a.legacy_queue_retirement:a.legacy_queue_transfer=True
if a.legacy_swap_wait and not a.legacy_queue_retirement:p.error('The bounded wait instrument requires the original completion candidate')
if a.legacy_queue_retirement and a.case not in ('positive','retirement-disabled'):p.error('Select completion or its same-candidate disabled control')
if a.case=='retirement-disabled' and not a.legacy_queue_retirement:p.error('Retirement-disabled requires the real completion candidate')
if a.legacy_queue_transfer:a.legacy_gop_validation=True
if a.case=='transfer-disabled' and not a.legacy_queue_transfer:p.error('Transfer-disabled requires the actual queue transfer candidate')
if a.legacy_gop_validation:a.legacy_logical_pm=True
if a.case=='validation-disabled' and (not a.legacy_gop_validation or a.legacy_swap_validate):p.error('Validation-disabled control requires the own validator candidate and its normal return observation')
if a.legacy_logical_pm and not a.legacy_swap:p.error('Logical scanout scheduling requires the original swap instrument')
if a.legacy_swap_submit and not a.legacy_swap:p.error('--legacy-swap-submit requires --legacy-swap')
if a.legacy_swap_decision and (not a.legacy_swap or a.legacy_swap_submit):p.error('Select one original swap observation')
if a.legacy_swap_validate and (not a.legacy_swap or a.legacy_swap_submit or a.legacy_swap_decision):p.error('Select one original swap observation')
if a.legacy_swap_kick and (not a.legacy_gop_validation or a.legacy_swap_validate or a.legacy_swap_submit or a.legacy_swap_decision or a.case!='positive'):p.error('Queue kick requires the enabled validator and its positive GPU input')
if a.legacy_swap and (a.compose or a.resources or a.present):p.error('Select one presentation instrument')
if a.legacy_swap:a.bgra=True
if a.compose and a.resources:p.error('Select composition or resource instrument')
if a.compose:a.present=True
if a.resources:a.present=True
if a.present:a.bgra=True
if a.bgra:a.iosurface=True
if a.iosurface and not a.metal_api:p.error('IOSurface requires --metal-api')
broker_kind='offline-metal-depth-stencil' if a.depth_stencil else 'offline-metal-private-texture' if a.private_texture else 'offline-renderbox-draw' if a.renderbox_draw else 'offline-renderbox-device' if a.renderbox_device else ('offline-metal-addon'+('' if a.plugin_control=='full' else '-'+a.plugin_control)) if a.plugin_addon else 'offline-metal-plugin' if a.plugin_bundle else 'offline-metal-shared-surfaces' if a.shared_surfaces else 'offline-metal-processes'
kind=(broker_kind+('-'+a.case if a.case in ('without-container','without-client') else '')) if a.broker_processes else 'offline-legacy-swap-wait' if a.legacy_swap_wait else 'offline-legacy-swap' if a.legacy_swap else 'offline-gop-composition' if a.compose else 'offline-gop-resources' if a.resources else 'offline-gop-presentation' if a.present else 'offline-metal-bgra' if a.bgra else 'offline-metal-iosurface' if a.iosurface else 'offline-metal-api' if a.metal_api else 'offline-gpu-transport'
OUT=ROOT/'build'/kind
base='build/xnu-prelink/native-owner-offline-gpu-depth-stencil-candidate' if a.broker_processes else 'build/xnu-prelink/native-owner-legacy-display-completion-candidate' if a.legacy_queue_retirement else 'build/xnu-prelink/native-owner-legacy-display-transfer-ready-candidate' if a.legacy_queue_transfer else 'build/xnu-prelink/native-owner-legacy-display-validate-candidate' if a.legacy_gop_validation else 'build/xnu-prelink/native-owner-legacy-display-pm-candidate' if a.legacy_logical_pm else 'build/xnu-prelink/native-owner-legacy-display-scale-candidate' if a.legacy_swap else 'build/xnu-prelink/native-owner-gop-present-candidate' if a.present else 'build/xnu-prelink/native-owner-console-bounds-candidate'
oslib=ROOT/'.cache/firmware/target-volumes/os-mount/System/Library'
paths=[oslib/'Frameworks/QuartzCore.framework/default.metallib',oslib/'PrivateFrameworks/RenderBox.framework/default.metallib']
cmd=['python3','scripts/probe-darwinboot-xnu.py','--kernel',base+'.macho','--prelink-report',base+'.json',
    '--output','build/darwinboot-owner-hvf-'+kind+('-cpu-contexts' if a.broker_processes else '')+('' if a.case in ('positive','without-container','without-client') else '-'+a.case),
    '--virtio-udif-image','.cache/firmware/target-volumes/044-76040-038.dmg',
    '--virtio-extra-block-image','.cache/firmware/target-volumes/044-76034-038.dmg',
    '--virtio-mmio-fdt','build/virtio-block-fixture/qemu-virt.dtb',
    '--root-match-volume-uuid','04769D26-2CA0-4825-B443-E2E5F88300F2',
    '--trust-cache','build/'+kind+'/offline-trust.bundle',
    '--armvirt','--armcpu','--qemu-vmm-present','--qemu-accel','hvf',
    '--owned-memory-size','0x20000000','--nvram-proxy','--crypto-hash-method','sha2-384',
    '--amfi-platform-only','--load-apfs','--inspect-owner-root','--inspect-dyld-flags','--check-commpage',
    '--skip-initializer-traces','--timeout','60','--data-ramdisk','build/'+kind+'/compiler-data-32.cdr',
    '--qemu-ramfb','--inspect-boot-video']
if a.legacy_queue_retirement and a.case!='retirement-disabled':cmd+=['--legacy-display-retire']
if a.legacy_queue_transfer:
    cmd[cmd.index('--output')+1]+='-completion' if a.legacy_queue_retirement else '-transfer-ready'
    if a.case not in ('default-off','validation-disabled','transfer-disabled'):cmd+=['--legacy-display-transfer','--inspect-gop-scanout-bytes','1920000']
if a.legacy_gop_validation:
    cmd[cmd.index('--output')+1]+='-driver'
    if a.case not in ('default-off','validation-disabled'):cmd+=['--legacy-display-validate']
if a.legacy_logical_pm:
    cmd[cmd.index('--output')+1]+='-pm'
    if a.case!='default-off':cmd+=['--legacy-display-logical-pm']
if a.iosurface:cmd+=['--load-iogpu']
if a.broker_processes and a.case!='default-off':cmd+=['--offline-gpu-broker']
if a.broker_processes and a.case in ('without-container','without-client'):cmd+=['--inspect-mac-policies']
if a.legacy_swap and a.case!='default-off':cmd+=['--load-mobile-graphics','--mobile-graphics-client-probe','--legacy-display-phase','4','--legacy-display-gop','--legacy-display-register','--legacy-display-unit-scale']
if a.present and a.case!='default-off':cmd+=['--load-mobile-graphics','--mobile-graphics-client-probe','--legacy-display-phase','3']
if a.present and a.case=='positive':cmd+=['--inspect-gop-scanout-bytes','1920000']
if a.case=='default-off':cmd+=['--follow-target-main']
elif a.broker_processes:
    cmd+=['--native-air-init']
    if a.broker_map_observe:
        cmd[cmd.index('--output')+1]+='-mmap-workers'+('' if a.broker_map_policy=='mac' else '-'+a.broker_map_policy.lower())
        if a.broker_map_policy=='mac':cmd+=['--break-symbol','_mac_file_check_mmap']
        else:
            observation=json.loads((ROOT/'build/darwinboot-owner-hvf-offline-metal-plugin-cpu-contexts-mmap-workers/gdb-stop.json').read_text())
            if observation['kernel_sha256']!=json.loads((ROOT/(base+'.json')).read_text())['candidate_sha256']:raise SystemExit('Registered policy observation belongs to another kernel')
            hook=next(r for r in observation['registered_mac_policies']['policies'] if r['name']==a.broker_map_policy)['hooks']['mpo_file_check_mmap']
            if not int(hook['address'],16) or len(hook['instructions'])!=128:raise SystemExit('Missing genuine registered mapping hook')
            cmd+=['--break-address',hook['address']]
        cmd+=['--finish-function','--inspect-current-process','--entry-process-name','air-native','--entry-min-pid','2','--entry-register-equals','2:5' if a.broker_map_policy=='mac' else '3:5','--entry-max-skips','1024','--inspect-mac-policies','--read-entry-region','1:0:80','--read-frame-locals']
    elif a.broker_spawn_observe:
        cmd[cmd.index('--output')+1]+='-'+a.broker_spawn_observe+('-policies' if a.broker_spawn_observe=='mac_vnode_check_exec' else '')
        cmd+=['--break-symbol','_'+a.broker_spawn_observe,'--finish-function','--inspect-current-process','--entry-process-name','air-native','--entry-max-skips','128','--read-frame-locals']
        if a.broker_spawn_observe=='mac_vnode_check_exec':cmd+=['--inspect-mac-policies']
        if a.broker_spawn_observe=='posix_spawn':cmd+=['--read-entry-region','1:0:40']
    elif a.case=='missing-device':cmd+=['--break-symbol','_native_gpu_broker_checkpoint']
    elif a.plugin_control=='tampered-code':cmd+=['--break-symbol','_cs_invalid_page','--inspect-current-process','--inspect-entry-user-state']
    else:cmd+=['--break-symbol','_exception_triage','--inspect-current-process','--inspect-entry-user-state','--read-saved-user-register','13:100']
elif a.legacy_swap_kick:
    cmd[cmd.index('--output')+1]+='-kick'
    if a.legacy_queue_transfer:cmd+=['--native-air-init','--break-symbol','_native_legacy_transfer_observed','--read-entry-region','1:0:a80','--capture-qemu-screen']
    else:cmd+=['--native-air-init','--break-address','0xfffffff005794030','--entry-after','_native_legacy_swap_validation_checkpoint','--read-entry-region','0:1000:800','--read-frame-locals','--capture-qemu-screen']
elif a.legacy_swap_validate:
    cmd[cmd.index('--output')+1]+='-validate'
    if a.legacy_gop_validation:cmd+=['--native-air-init','--break-symbol','_native_legacy_swap_validation_checkpoint','--read-entry-region','2:0:a80','--read-entry-region','3:0:100','--read-frame-locals','--capture-qemu-screen']
    else:cmd+=['--native-air-init','--break-address','0xfffffff005795bb4','--finish-function','--read-entry-region','1:0:a80','--read-entry-indirect','1:a40:100','--read-frame-locals','--capture-qemu-screen']
elif a.legacy_swap_decision:
    cmd[cmd.index('--output')+1]+='-decision'
    cmd+=['--native-air-init','--break-address','0xfffffff005790574','--read-frame-locals','--read-frame-indirect','0:-28:508','--capture-qemu-screen']
elif a.legacy_swap_submit:
    cmd[cmd.index('--output')+1]+='-submit'
    cmd+=['--native-air-init','--break-address','0xfffffff00578f224','--read-entry-region','0:1000:800','--read-entry-region','1:0:508','--read-entry-region','2:0:100','--read-frame-locals','--capture-qemu-screen']
elif a.legacy_swap:cmd+=['--native-air-init','--break-symbol','_exception_triage','--inspect-current-process','--inspect-entry-user-state','--read-saved-user-register','13:80','--capture-qemu-screen']
else:cmd+=['--native-air-init','--break-symbol','_exit','--read-entry-region','1:0:8']
if a.plugin_bundle and not a.broker_map_observe and a.plugin_control!='tampered-code':cmd+=['--read-saved-user-register','14:1000' if a.renderbox_draw else '14:200']
if a.case in ('missing-device','default-off'):
    subprocess.run(cmd,cwd=ROOT,timeout=180,check=True)
    print('Absent console/default-off control observation recorded');raise SystemExit(0)
with tempfile.TemporaryDirectory(prefix='native-gpu-',dir='/tmp') as directory:
    sock=Path(directory)/'gpu.sock'
    host_suffix=('-cpu-contexts' if a.broker_processes else '')+('-'+a.broker_spawn_observe if a.broker_spawn_observe else '')+(('-mmap-workers'+('' if a.broker_map_policy=='mac' else '-'+a.broker_map_policy.lower())) if a.broker_map_observe else '')+('-disabled' if a.case=='validation-disabled' else '-transfer-disabled' if a.case=='transfer-disabled' else '')+('-retire-disabled' if a.case=='retirement-disabled' else '')+('-completion' if a.legacy_queue_retirement else '-transfer-ready' if a.legacy_queue_transfer else '')+('-driver' if a.legacy_gop_validation else '')+('-pm' if a.legacy_logical_pm else '')+('-kick' if a.legacy_swap_kick else '-validate' if a.legacy_swap_validate else '-decision' if a.legacy_swap_decision else '-submit' if a.legacy_swap_submit else '')
    with (OUT/('host'+host_suffix+'-report.json')).open('w') as report,(OUT/('host'+host_suffix+'-stderr.log')).open('w') as errors:
        host=subprocess.Popen([str(ROOT/'build/host-metal/host-metal-originals'),*map(str,paths),'--metal-session-socket' if a.broker_processes else '--metal-socket' if a.metal_api else '--socket',str(sock)],stdout=report,stderr=errors)
        try:
            deadline=time.monotonic()+15
            while not sock.exists():
                if host.poll() is not None or time.monotonic()>=deadline:raise SystemExit('Host GPU socket did not become ready')
                time.sleep(.02)
            cmd+=['--virtio-console-socket',str(sock)]
            result=subprocess.run(cmd,cwd=ROOT,timeout=180)
            if result.returncode:raise SystemExit(result.returncode)
            if not a.broker_spawn_observe and not a.broker_map_observe and a.case!='without-container' and a.plugin_control=='full' and not a.renderbox_device and host.wait(timeout=5):raise SystemExit('Real host GPU backend failed')
        finally:
            if host.poll() is None:host.terminate();host.wait(timeout=5)
print('Offline transport observation recorded; inspect actual native exit, DMA and host GPU results')
