#!/usr/bin/env python3
"""Verify the original SpringBoard initializer really returns the native GOP mode."""
import json
from pathlib import Path
import runpy
import struct
ROOT=Path(__file__).resolve().parents[1]
base=runpy.run_path(str(ROOT/'scripts/check-system-framebuffer-client.py'))
require=base['require'];sha=base['sha'];plan=base['plan']
require(base['args'].profile=='scale','Use the current qualified unit-scale candidate')
path=ROOT/'build/darwinboot-owner-hvf-legacy-display-start-scale-mode/gdb-stop.json';d=json.loads(path.read_text())
require(d['kernel_sha256']==plan['candidate_sha256'] and not d['bounded_timeout_interrupted'] and
        d['stop_symbol']=='original-display-mode-return' and d['original_launchd_main_executed'] and
        d['followed_main_entry']['first_instruction_completed'],'Real original boot and selected mode-return observation')
f=d['followed_display_query'];p=f['plan']
require(p['mode']=='user-return' and p['query']==0x19f3d0500 and p['return_checkpoint']==476 and
        p['original_mode_initializer_sha256']=='ca4857e6617670f2369a0a6eb68be09e29135ce5dfda19ac1ea829229f0cc0ec' and
        f['observed'] and f['entry_process']['name']==f['actual_process']['name']=='SpringBoard' and
        f['entry_process']['thread']==f['actual_process']['thread']==f['activated_process']['thread'],
        'Exact unchanged original initializer and actual selected SpringBoard thread')
slide=int(f['cache_slide'],16)
require(int(f['query'],16)==p['query']+slide and int(f['epilogue_pc'],16)==p['query']+slide+476 and
        f['entry_process']['shared_region_slide']==slide and
        f['caller_restored'] and f['return_pc']==f['caller']==d['pc'] and
        f['return_stack']==f['entry_stack']==d['sp'] and
        f['entry_bytes']==f['query_bytes_after_fault']==p['query_prefix'] and int(d['pstate'],16)&31==0,
        'Actual cache activation, unmodified instructions and real RET restore the original caller/stack at EL0')
args=[int(v,16) for v in f['entry_arguments']]
raw=bytes.fromhex(f['returned_object_bytes'])
require(int(f['return_value'],16)==args[0]!=0 and len(raw)==80,'Real nonnull original mode object returned')
isa,width,height,preferred,override,refresh,gamut,hdr,rotation,virtual=struct.unpack_from('<4Q2d3QB',raw)
require(isa and (width,height,preferred)==tuple(args[2:5])==(800,600,1) and
        override==0.0 and refresh==60.0 and (gamut,hdr,rotation,virtual)==(0,0,0,0),
        'Original returned object contains the actual GOP dimensions and explicit 1:1 logical scale')
state=d['native_legacy_display'];video=d['actual_boot_video']['pe_video']
require(state['stage']==10 and state['start_result']==state['dt_attached']==state['registration_calls']==1 and
        state['unit_scale_status']==0 and state['unit_scale_calls']==state['chosen_scale']==1 and
        state['chosen_rotation']==0 and not state['guard_slot'] and
        state['gop_physical']==video['v_baseAddr'] and state['gop_width']==width and state['gop_height']==height and
        state['gop_bytes']==video['v_rowBytes']*height==1920000,
        'Unit-scale policy is bound to the actual retained GOP mode/resource, without a guessed panel mode')
require(d['native_4k_mmu_observed'] and set(d['direct_user_commpage_shifts'].values())=={12} and
        d['original_amfi_table_owner_observed'] and d['owner_root_binding_audit']['boot_root_accepted'] and
        d['owner_root_binding_audit']['_native_owner_root_apple_autherr']==80 and
        d['actual_signature_failures']==dict(_cs_validate_page_bad_hash=0,_cs_validate_page_no_hash=0),
        'Active native CPU/user 4K, original AMFI/Apple rejection and independent owner-root acceptance remain intact')
(ROOT/'build/native-legacy-display/unit-scale-mode-checkpoint.json').write_text(json.dumps(dict(
    candidate_sha256=plan['candidate_sha256'],native_sha256=plan['native_sha256'],checkpoint_sha256=sha(path),
    actual_process=f['actual_process'],actual_original_initializer_return=True,
    width=width,height=height,logical_scale=preferred,original_refresh_rate_field=refresh,
    panel_timing_measured=False,original_instructions_modified=False,swap_contract_complete=False,
    system_metal_device=False,original_desktop=False,adreno_execution=False,hardware_tested=False),indent=2)+'\n')
print('PASS: unchanged original SpringBoard mode initializer returns a real 800x600, scale-1 mode to its actual caller')
print('Original validation passes naturally; actual swaps, system Metal, desktop and Adreno remain open')
