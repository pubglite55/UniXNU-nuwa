#!/usr/bin/env python3
"""Verify the real render-server reply and independently captured QEMU scanout."""
import hashlib
import json
from pathlib import Path
import plistlib
import struct
ROOT=Path(__file__).resolve().parents[1]
def require(value,reason):
    if not value:raise SystemExit(reason)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
plan=json.loads((ROOT/'build/xnu-prelink/native-owner-legacy-display-scale-candidate.json').read_text())
query_path=ROOT/'build/darwinboot-owner-hvf-legacy-display-start-scale-query/gdb-stop.json'
screen_path=ROOT/'build/darwinboot-owner-hvf-legacy-display-start-scale-exception-SpringBoard-screen/gdb-stop.json'
d=json.loads(query_path.read_text());screen=json.loads(screen_path.read_text())
for observation in (d,screen):
    require(observation['kernel_sha256']==plan['candidate_sha256'] and observation['native_4k_mmu_observed'] and
            observation['original_amfi_table_owner_observed'] and observation['owner_root_binding_audit']['boot_root_accepted'] and
            observation['actual_signature_failures']==dict(_cs_validate_page_bad_hash=0,_cs_validate_page_no_hash=0),
            'Same exact candidate, real native 4K, original AMFI/root and zero signature failures')
require(d['stop_symbol']=='original-display-query-return' and not d['bounded_timeout_interrupted'],
        'Actual unchanged original display query returns normally')
f=d['followed_display_query']
require(f['observed'] and f['entry_process']['name']==f['actual_process']['name']=='SpringBoard' and
        f['entry_process']['thread']==f['actual_process']['thread'] and f['caller_restored'] and
        f['entry_bytes']==f['query_bytes_after_fault']==f['plan']['query_prefix'],
        'Real selected original query, unchanged instructions and restored caller')
port,reply=f['checkpoints']
require(port['stage']=='server-port' and int(port['x0'],16)!=0 and reply['stage']=='display-reply' and int(reply['x0'],16)==0,
        'Real nonzero CARenderServer port and actual successful CASGetDisplays reply')
body=bytes.fromhex(reply['output_bytes']);require(len(body)==int.from_bytes(bytes.fromhex(reply['output_length']),'little'),
        'Actual reply extent matches captured bytes')
displays=plistlib.loads(body)
primary=[v for v in displays if v.get('kCADisplayDeviceName')=='primary']
require(isinstance(displays,list) and len(primary)==1 and primary[0]['kCADisplayName']=='LCD' and
        primary[0]['kCADisplayFrameCount']==0 and primary[0]['kCADisplayDirtyFrameCount']==0 and
        int.from_bytes(bytes.fromhex(f['main_display_bytes']),'little') and int.from_bytes(bytes.fromhex(f['displays_bytes']),'little'),
        'The original server reports its LCD and original nonnull display objects, with initial counters zero')
capture=screen['qemu_screen_capture'];image=screen_path.parent/capture['file'];raw=image.read_bytes()
require(screen['bounded_timeout_interrupted'] and capture['width']==800 and capture['height']==600 and
        raw[:8]==bytes.fromhex('89504e470d0a1a0a') and struct.unpack_from('>2I',raw,16)==(800,600) and
        len(raw)==capture['bytes'] and sha(image)==capture['sha256'],
        'Actual QMP screendump produces the recorded bounded-run 800x600 PNG')
# This exact screenshot was visually inspected. It is still the loader GOP
# content, not evidence of an original UI frame. No image reconstruction or
# CPU renderer is used to create the QMP output.
require(capture['sha256']=='e90f3f3195332e37f9a95d7416dc79ca2fa63d08ed3e170f71704a5678000aaf',
        'Exact independently inspected loader-content screenshot; changed images require fresh inspection')
metal_path=ROOT/'build/darwinboot-owner-hvf-legacy-display-start-scale-metal/gdb-stop.json'
metal=json.loads(metal_path.read_text());m=metal['followed_display_query'];mp=m['plan']
require(metal['kernel_sha256']==plan['candidate_sha256'] and not metal['bounded_timeout_interrupted'] and
        metal['stop_symbol']=='original-default-metal-device-return' and m['observed'] and
        m['entry_process']['name']==m['actual_process']['name']=='backboardd' and
        m['entry_process']['thread']==m['actual_process']['thread'] and m['caller_restored'] and
        m['return_pc']==m['caller']==metal['pc'] and m['return_stack']==m['entry_stack']==metal['sp'] and
        m['entry_bytes']==m['query_bytes_after_fault']==mp['query_prefix'] and
        mp['query']==0x187ac8668 and mp['return_checkpoint']==176 and
        mp.get('original_function_sha256',mp.get('original_mode_initializer_sha256'))==
        '8005e91f7637cf800246ae2130936f45cb57d6a0891a77c61f1f563e9b058d20' and
        int(m['return_value'],16)==0 and m['returned_object_bytes'] is None,
        'Actual unchanged original MTLCreateSystemDefaultDevice returns nil to the real backboardd caller')
require(metal['native_4k_mmu_observed'] and metal['original_amfi_table_owner_observed'] and
        metal['owner_root_binding_audit']['boot_root_accepted'] and
        metal['actual_signature_failures']==dict(_cs_validate_page_bad_hash=0,_cs_validate_page_no_hash=0),
        'Original Metal observation preserves AMFI/root/native CPU 4K')
(ROOT/'build/native-legacy-display/render-server-checkpoint.json').write_text(json.dumps(dict(
    candidate_sha256=plan['candidate_sha256'],query_checkpoint_sha256=sha(query_path),screen_checkpoint_sha256=sha(screen_path),metal_checkpoint_sha256=sha(metal_path),
    screenshot_sha256=capture['sha256'],separate_bounded_vm_observations=True,
    original_render_server_replied=True,actual_original_backboardd_metal_device=None,initial_primary_frame_count=0,actual_scanout_content='previous loader frame',
    original_desktop=False,system_metal_device=False,adreno_execution=False,hardware_tested=False),indent=2)+'\n')
print('PASS: real original render server replies successfully with an LCD; actual QMP scanout capture qualified')
print('Actual backboardd receives nil from original Metal discovery; initial frames are zero and scanout remains loader content')
