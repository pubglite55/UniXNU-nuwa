#!/usr/bin/env python3
"""Qualify actual SpringBoard display replies and backboardd registry discovery."""
import hashlib
import json
from pathlib import Path
import plistlib

ROOT = Path(__file__).resolve().parents[1]
expected = 'a4a5fd00dbfb3d41ffe7913cc31b14a2db58e27f5d89129d64018e534b9dc309'
native = 'ba60f353a90b61fb6d63425648aeb4475a2c237ed19800d60d2f583cea035bb3'
image = ROOT / 'build/xnu-prelink/native-owner-pgz-fixed-candidate.macho'


def require(value, message):
    if not value:
        raise SystemExit(message)


require(hashlib.sha256(image.read_bytes()).hexdigest() == expected, 'Exact unchanged native candidate')
for actor, mode, function in (('springboard', 'query', 0x189549038), ('backboard', 'discovery', 0x1b63da630)):
    d = json.loads((ROOT / f'build/darwinboot-owner-hvf-{actor}-display-{mode}/gdb-stop.json').read_text())
    q = d['followed_display_query']
    p = q['plan']
    r = {name: int(value, 16) for name, value in d['system_registers'].items()}
    require(d['kernel_sha256'] == expected and p['native_sha256'] == native and d['qemu_accelerator'] == 'hvf' and
            not d['bounded_timeout_interrupted'] and d['native_4k_mmu_observed'] and
            r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and r['SCTLR_EL1'] & 1 and
            r['TTBR0_EL1'] and r['TTBR1_EL1'] and d['direct_user_commpage_shifts'] == {'fffff4025:1': 12, 'fffff4037:1': 12},
            'Bounded native-4K hardware and actual user ABI')
    require(d['original_launchd_main_executed'] and d['followed_main_entry']['first_instruction_completed'] and
            q['observed'] and q['caller_restored'] and q['entry_bytes'] == q['query_bytes_after_fault'] == p['query_prefix'] and
            int(q['entry_pstate'], 16) & 31 == 0 and q['entry_stack'] == q['return_stack'] and
            q['entry_process'] == q['actual_process'] and
            q['actual_process']['proc'] == q['activated_process']['proc'] and
            q['actual_process']['task'] == q['activated_process']['task'] and
            q['actual_process']['name'] == ('SpringBoard' if mode == 'query' else 'backboardd'),
            'Exact actual process/thread, authenticated original instructions and same-stack completion')
    slide = int(q['cache_slide'], 16)
    require(q['actual_process']['shared_region_slide'] == slide and slide & 4095 == 0 and
            0 <= slide <= p['max_slide'] and int(q['query'], 16) == function + slide and
            p['cache_uuid'] == '590d839a82d230f1a17d0cc053420f73' and
            p['local_symbols_uuid'] == 'a1a859a2479c31998a34f4afbd808cf5' and
            p['main_import_offset'] == 0x6c0d0 and p['unslid_import'] == 0x1f4843c60 and
            p['query'] == function and not p['original_files_modified'],
            'Original cache/local symbols, main binding and actual selected task shared-region slide')
    if mode == 'query':
        require(any(e.get('result') == 0 and e.get('return_process') == q['activated_process'] for e in q['activation_events']),
                'Real selected-process shared-region syscall returned success before observing its user code')
    else:
        require(not q['activation_events'] and q['actual_process']['shared_region_slide'] == int(q['launchd_cache_slide'], 16),
                'Actual discovery task region independently confirms the initial address; no invented syscall activation')
    require(d['owner_root_binding_audit']['boot_root_accepted'] and
            d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80 and
            d['owner_boot_manifest']['status'] == 0 and d['original_amfi_table_owner_observed'] and
            d['original_crypto_initialized_observed'] and
            d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
            d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0 and
            not d['functional_ipados_boot_demonstrated'] and not d['sheng_hardware_tested'],
            'Original security checks, real independent owner roots and offline scope')
    if mode == 'query':
        port, reply = q['checkpoints']
        require(port['stage'] == 'server-port' and int(port['x0'], 16) != 0 and reply['stage'] == 'display-reply' and
                int(reply['x0'], 16) == 0 and len(bytes.fromhex(reply['output_bytes'])) ==
                int.from_bytes(bytes.fromhex(reply['output_length']), 'little') == 42 and
                plistlib.loads(bytes.fromhex(reply['output_bytes'])) == [] and
                q['main_display_bytes'] == q['displays_bytes'] == '00' * 8 and q['return_pc'] == q['caller'],
                'Actual SpringBoard server request succeeds with a real empty plist array and no main display')
        print('PASS: actual SpringBoard CASGetDisplays succeeds with []; original query returns with no main CADisplay')
    else:
        event, = q['checkpoints']
        require(event['stage'] == 'registry-arm-io' and int(event['x0'], 16) != 0 and
                q['discovery_counts']['reference_count'] == q['discovery_counts']['enumerated_count'] == '00' * 4 and
                q['discovery_counts']['display_count'] == 'E14' and
                int(q['epilogue_pc'], 16) == int(q['query'], 16) + p['return_checkpoint'] and
                'return_pc' not in q, 'Actual backboardd finds arm-io but counts zero display pipes/instances; unreadable length is not zero')
        print('PASS: actual backboardd original discovery reaches its RET with zero display pipes/instances; no RET execution claim')

d = json.loads((ROOT / 'build/darwinboot-owner-hvf-display-exception-process/gdb-stop.json').read_text())
s = json.loads((ROOT / 'build/native-user-exception/display-process-symbolication.json').read_text())
require(d['kernel_sha256'] == s['kernel_sha256'] == expected and d['stop_symbol'] == '_exception_triage' and
        not d['bounded_timeout_interrupted'] and d['actual_process']['name'] == 'SpringBoard' and
        int(d['observed_function_entry_arguments'][0], 16) == 6 and
        s['local_symbols_uuid_matches'] and s['frames'][0]['nearest_local_symbol'] ==
        '-[FBSDisplayMonitor _initWithBookendObserver:transformer:]' and
        s['static_original_assertion'] == dict(literal_va='0x1e7a9bf68', text='failed to find the main CADisplay', runtime_string_captured=False),
        'Actual SpringBoard process, original FrontBoard exception and UUID-bound original assertion reference')
print('PASS: original display-monitor exception belongs to real SpringBoard; no functional UI or hardware qualification')
