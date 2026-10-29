#!/usr/bin/env python3
"""Qualify actual native union roots and retained original signature/media refusal."""
import hashlib
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]
base = runpy.run_path(str(ROOT / 'scripts/check-original-launchd-main-checkpoints.py'))
require = base['require']
old = base['candidate']('native-owner-union-systemos-candidate',
    'b18cf593c77b268091a85de354edd0a797ea2fbfa41ebaeb70d41f8964a0653e',
    '67718fdf31cce1ad6dd1ed7f65ae6eff32ca4d5fe94a8f54f41092793d492700')
new = base['candidate']('native-owner-native-union-root-candidate',
    '654fdd0c7fcd80126c2dd45478e1030bc4e692b13977c52c2a50d878c8735396',
    '588a44127f27f94a1f5033e27783e97060103697ef11b4fce4eeb173ba208173')
continuation, page, fault, missing, exception = [base['report']('owner-hvf-' + name) for name in (
    'union-systemos-first-abort', 'union-libobjc-page', 'native-union-main-fault',
    'native-union-missing-systemos', 'native-union-first-exception')]
for d, expected in ((continuation, old), (page, old), (fault, new), (missing, new), (exception, new)):
    require(d['kernel_sha256'] == expected and d['qemu_accelerator'] == 'hvf' and
            d['native_4k_mmu_observed'] and d['kernel_page_globals'] == dict(_PAGE_SHIFT_CONST=12,
                _page_shift=12, _page_shift_user32=12, _page_size=4096) and
            d['owner_root_binding_audit']['boot_root_accepted'] and
            d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80 and
            d['original_amfi_table_owner_observed'] and d['original_crypto_table_owner_observed'] and
            d['native_virtio_globals']['_native_virtio_read_failures'] == 0 and
            d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0 and
            not d['functional_ipados_boot_demonstrated'] and not d['sheng_hardware_tested'],
            'Exact original components and real native-4K owner root; no UI or hardware claim')
for d in (continuation, page, fault, exception):
    m = d['owner_cache_mount']
    require(m['_native_owner_cache_stage'] == 6 and m['_native_owner_cache_status'] == 0 and
            m['_native_owner_cache_readonly'] == m['_native_owner_cache_authorized'] == m['_native_owner_cache_root_recheck'] == 1 and
            d['owner_boot_manifest']['status'] == 0 and d['scratch_data']['state']['_native_owner_data_readonly'] == 0,
            'Actual owner-authenticated read-only SystemOS and separate writable Data')
for d in (fault, exception):
    g = d['actual_root_composition']
    require(g['_native_owner_cache_actual_mount_flags'] & 0x21 == 0x21 and
            g['_native_owner_cache_native_union'] == 1 and g['_native_owner_cache_original_root'] and
            g['_native_owner_cache_current_root'] == g['_rootvnode'] != g['_native_owner_cache_original_root'] and
            'owner_cache_carrier' not in d, 'Actual native union root graph with the old carrier compiled out')
for d in (continuation, page):
    c = d['owner_cache_carrier']
    require(c['_native_owner_cache_carrier_accepts'] == c['_native_owner_cache_carrier_rejects'] == 0,
            'Earlier build did not invoke the carrier exception')
require(continuation['bounded_timeout_interrupted'] and continuation['stop_symbol'] == 'timeout-interrupt' and
        continuation['native_signature_hash_cache']['_cs_native4k_page_checks'] == 91235,
        'Bounded continuation did not reach the prior abort; it is not UI proof')
lib = (ROOT / '.cache/firmware/target-volumes/systemos-mount/usr/lib/libobjc-trampolines.dylib').read_bytes()
raw = bytes.fromhex(page['entry_regions']['3:0:1000']['bytes'])
require(hashlib.sha256(lib).hexdigest() == '8089b4432232e56464ce724e1ef334e5b95dfc0eaa33eacc8eb2a76b669744d4' and
        raw == lib[:4096] and hashlib.sha256(raw).hexdigest() == '369b2597e7feb43c6532391dc14407de2d178c038b67bfc4afb56b2e68ba085a' and
        page['stop_symbol'] == '_cs_validate_hash' and page['function_return_stack_matched'] and int(page['x0'], 16) == 1 and
        int(page['function_entry_arguments'][2], 16) == 0 and page['entry_regions']['4:0:8']['bytes'] == '0010000000000000' and
        page['entry_regions']['5:0:4']['bytes'] == '00000000', 'Real original library HEADER page validates; no executable-page claim')
require(page['entry_kernel_bytes_match']['bytes'] == 'fac8b0f655abd6235bb6f793ebfe747338d134af', 'Select original library CodeDirectory')
f = fault['own_mapped_page_mutation']
require(f['file_page'] == 81920 and f['byte_in_page'] == 3976 and f['before'] == 255 and f['after'] == 254 and
        f['page_sha256_before'] == '32f1004a16014e6f56fc8b18dcb4e7bed2bb38353be71725b881cfc09d462621' and
        not f['registers_or_validation_state_modified'] and not fault['original_launchd_main_executed'] and
        fault['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=1, _cs_validate_page_no_hash=0) and
        fault['fatal_user_exit'] == dict(cs_status='CS_KILLED', prefix='initproc failed to start', namespace=3, code=2, description='none'),
        'Actual original launchd byte corruption must remain refused before main')
require(missing['stop_symbol'] == '_panic' and missing['owner_cache_mount']['_native_owner_cache_stage'] == 1 and
        missing['owner_cache_mount']['_native_owner_cache_status'] == 80 and
        missing['actual_root_composition']['_native_owner_cache_native_union'] == 0 and
        missing['native_ram_block']['state']['_native_ram_block_writes'] == 0,
        'Missing SystemOS must refuse before composition or Data writes')
for d in (continuation, page, missing, exception):
    require(d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0), 'No unrelated code hash failures')
require(exception['stop_symbol'] == '_panic' and not exception['bounded_timeout_interrupted'] and
        exception['argument_memory']['x0'].startswith('metadata %p corresponding to addr %p being freed to zone') and
        not exception.get('entry_user_state_candidates'), 'Preserve actual earlier IPC zone refusal, no invented user exception')
print('PASS: native union root, original libobjc header signature validation, writable Data')
print('PASS: carrier disabled; real main-byte corruption and missing SystemOS remain refused')
print('Open: actual IPC zone panic; executable libobjc page, functional UI, persistent Data and sheng hardware remain unqualified')
