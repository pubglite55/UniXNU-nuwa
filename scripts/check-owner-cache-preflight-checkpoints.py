#!/usr/bin/env python3
"""Qualify real 512-MiB ownership, complete original cache preflight and genuine mount-policy refusal."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
import native_prelink as np


def require(value, message):
    if not value:
        raise SystemExit(message)


def report(name):
    return json.loads((ROOT / ('build/darwinboot-' + name) / 'gdb-stop.json').read_text())


runs = [report(name) for name in ('owner-hvf-512-shared-region', 'owner-hvf-512-cache-permission')]
candidate = ROOT / 'build/xnu-prelink/native-owner-dt-panic-candidate'
plan = json.loads(candidate.with_suffix('.json').read_text())
kernel = candidate.with_suffix('.macho').read_bytes()
require(hashlib.sha256(kernel).hexdigest() == plan['candidate_sha256'] ==
        'f3611f1aa0a472122196134101237384de931d4d78d6f02d3c7013a63405898d' and plan['native_sha256'] ==
        '926d1e6bc223b12d482e5b48c0e3fd43173108168f54c2e1cb5cf3042f0f8eae' and len(plan['components']) == 15,
        'Require exact original-component mount candidate')
original = (ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed').read_bytes()
require(hashlib.sha256(original).hexdigest() == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7', 'Require supplied target')
old, meta = np.macho(original), np.macho(kernel)
for e in plan['extents']:
    if e['segment'] == '__TEXT_EXEC':
        at = np.backed_offset(meta['segments'], e['va'], e['size'], len(kernel))
        prev = np.backed_offset(old['segments'], e['va'] - plan['slide'], e['size'], len(original))
        require(kernel[at:at + e['size']] == original[prev:prev + e['size']], 'Every original executable extent must remain unchanged')
trust = (ROOT / 'build/original-static-system-trust/original-static-system.bundle').read_bytes()
require(hashlib.sha256(trust).hexdigest() == '7416ca4f8377146626bb284e2133c76bee6cb4e3ee0af5d648b186235a7323a7' and
        struct.unpack_from('<II', trust) == (2, 12), 'Require only the two original trust modules')
second = struct.unpack_from('<I', trust, 8)[0]
require(hashlib.sha256(trust[12:second]).hexdigest() == 'da88460e6e513438d5307e5c526f76497a74754476a24da29f239f0c90120fc2' and
        hashlib.sha256(trust[second:]).hexdigest() == 'd121ba89167e03aafd00fa687c30cd8ebc4ccafd10c1408adb2ba3de12403651',
        'No original trust byte or own code entry may be substituted')
for d in runs:
    require(d['kernel_sha256'] == plan['candidate_sha256'] and d['qemu_accelerator'] == 'hvf' and
            d['qemu_cpu_model'] == 'host' and d['offline_qemu_vmm_present_declared'] and not d['bounded_timeout_interrupted'] and
            d['trust_cache_bundle_sha256'] == hashlib.sha256(trust).hexdigest(), 'Exact bounded HVF candidate and unchanged original trust')
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and r['SCTLR_EL1'] & 1 and
            r['TTBR0_EL1'] and r['TTBR1_EL1'] and r['CNTFRQ_EL0'] == 24000000 and d['kernel_page_globals'] ==
            dict(_PAGE_SHIFT_CONST=12, _page_shift=12, _page_shift_user32=12, _page_size=4096), 'Actual native-4K hardware and ABI globals')
    require(d['original_amfi_table_owner_observed'] and d['original_crypto_initialized_observed'] and
            d['original_crypto_table_owner_observed'] and d['owner_root_binding_audit']['boot_root_accepted'] and
            d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80, 'Real AMFI/crypto and owner root proof')
    require(d['actual_physical_memory'] == dict(_gPhysBase=0x4807c000, _gPhysSize=0x20000000,
            _mem_size=0x20000000, _mem_actual=0x20000000), 'All actual native memory sizes must match the real UEFI allocation')
    require(d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
            d['native_signature_hash_cache'] == dict(_cs_native4k_hash_cache_version=1, _cs_native4k_full_blocks=201083,
            _cs_native4k_page_checks=212, _cs_native4k_ready_blobs=53), 'Actual complete original signing-block preflight and native-page checks')
    require(d['native_virtio_globals']['_native_virtio_read_failures'] == 0 and
            d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0 and
            d['native_virtio_integrity']['_native_virtio_verified_devices'] == 2, 'Both media remain independently authenticated')
    require(d['actual_panic_region'] == dict(_gPanicBase=0, _gPanicSize=0, _panic_info=0) and
            d['dyld_startup_flags'] == dict(_dyld_flags=8, _native_owner_cache_dyld_flags=8, actual_commpage_flags=8), 'Retain actual authenticated startup mode and no phantom panic mapping')
    state = d['owner_cache_mount']
    require(state['_native_owner_cache_stage'] == 6 and state['_native_owner_cache_status'] == 0 and
            state['_native_owner_cache_mount_status'] == 0 and state['_native_owner_cache_readonly'] == 1 and
            state['_native_owner_cache_authorized'] == state['_native_owner_cache_root_recheck'] == 1 and
            state['_native_owner_cache_selected_device'] == state['_native_owner_cache_mounted_device'], 'Actual readonly SystemOS mount and separate root recheck')
    require(d['stop_symbol'] == '_shared_region_map_and_slide_2_np' and d['finished_function_entry'] == '0xfffffff00bd5cb28' and
            d['function_return_stack_matched'] and d['function_return_target'] == d['pc'] and int(d['x0'], 16) == 1 and
            not d['ipados_userspace_boot_demonstrated'], 'Actual shared-region syscall returns EPERM on the same stack; no mapping claim')
permission = runs[1]
require(permission['cstring_start_event']['pc'] == '0xfffffff00bd5e26c' and not permission['cstring_log_exhausted'] and
        any(e['value'].endswith("not on process' root volume nor preboot volume\n") and e['caller'] == '0xfffffff00bd5f4a0'
            for e in permission['cstring_events']), 'Observe actual native carrier-volume policy refusal after setup begins')
for name in ('owner-hvf-512-shared-region', 'owner-hvf-512-cache-permission'):
    folder = ROOT / ('build/darwinboot-' + name)
    require(hashlib.sha256((folder / 'esp/EFI/UniXNU/Payloads/DarwinBoot.efi').read_bytes()).hexdigest() ==
            'b5bf6baa3bad99ad2a10791359480af77053c828c0635ddbc65e6d30c1a3c8e6', 'Pin exact tested DarwinBoot loader')
    require('owned=0x20000000' in (folder / 'gdb-uart.log').read_text(), 'Actual UEFI handoff must own 512 MiB')
print('PASS: real 512-MiB ownership, 53 original signature objects, 201083 whole signing blocks and 212 native-4K pages')
print('PASS: shared-region syscall genuinely returns EPERM; original cache carrier-volume policy is the observed cause')
print('Full shared-cache mapping, launchd main and bare-metal PMGR remain open')
