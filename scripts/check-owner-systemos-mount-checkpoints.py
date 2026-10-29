#!/usr/bin/env python3
"""Qualify actual owner-authenticated SystemOS mounting and genuine refusals."""
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


mounted, missing, continuation, file_call = (report(name) for name in (
    'owner-systemos-mounted', 'owner-systemos-missing-enforced', 'owner-original-cache-load', 'owner-cache-openat'))
candidate = ROOT / 'build/xnu-prelink/native-owner-systemos-mount-candidate'
plan = json.loads(candidate.with_suffix('.json').read_text())
kernel = candidate.with_suffix('.macho').read_bytes()
require(hashlib.sha256(kernel).hexdigest() == plan['candidate_sha256'] ==
        '6631d27898e27565fb9ce8eb03cc40f2d74fb1aeb36c69da1e1a0f893bf0fe51' and plan['native_sha256'] ==
        'dfdc5b20b8562885de687afe8bf4fda8e9da9b4b20d7111a12ffe985d9a84d71' and len(plan['components']) == 15,
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
for d in (mounted, missing, continuation, file_call):
    require(d['kernel_sha256'] == plan['candidate_sha256'] and not d['bounded_timeout_interrupted'] and
            d['trust_cache_bundle_sha256'] == hashlib.sha256(trust).hexdigest(), 'Require same bounded candidate and exact original trust input')
    regs = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(regs['TCR_EL1'] >> 14 & 3 == 0 and regs['TCR_EL1'] >> 30 & 3 == 2 and regs['SCTLR_EL1'] & 1 and
            regs['TTBR0_EL1'] and regs['TTBR1_EL1'] and d['original_amfi_table_owner_observed'] and
            d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'], 'Require active native 4K and genuine original crypto/AMFI')
    root = d['owner_root_binding_audit']
    require(root['boot_root_accepted'] and root['_native_owner_root_apple_autherr'] == 80 and
            root['actual_uuid'] == '04769D26-2CA0-4825-B443-E2E5F88300F2', 'Original OS root proof must remain intact')
    require(d['native_virtio_globals']['_native_virtio_read_failures'] == 0 and
            d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0, 'No unauthenticated I/O may be exposed')
for d in (mounted, continuation, file_call):
    state = d['owner_cache_mount']
    require(state['_native_owner_cache_stage'] == 6 and state['_native_owner_cache_status'] == 0 and
            state['_native_owner_cache_mount_status'] == 0 and state['_native_owner_cache_readonly'] == 1 and
            state['_native_owner_cache_authorized'] == 1 and state['_native_owner_cache_root_recheck'] == 1 and
            state['_native_owner_cache_selected_device'] == state['_native_owner_cache_mounted_device'] == 0x01000004 and
            state['actual_device_path'] == '/dev/disk2s1' and d['native_virtio_integrity']['_native_virtio_verified_devices'] == 2,
            'Real APFS user mount, actual dev_t/UUID binding and separate root recheck must pass')
require(mounted['stop_symbol'] == '_native_owner_cache_checkpoint' and mounted['function_return_stack_matched'] and
        mounted['native_virtio_globals']['_native_virtio_read_requests'] == 304 and
        mounted['native_virtio_integrity']['_native_virtio_verified_blocks'] == 478, 'Observe actual post-mount same-stack checkpoint')
for value in mounted['indirect_memory'].values():
    t = value['translation']
    require(t['leaf_level'] == 3 and t['leaf_bytes'] == 4096 and t['ap'] == 2 and t['pxn'] and t['uxn'], 'Private metadata and key copies retain native-4K RO/NX PTEs')
state = missing['owner_cache_mount']
require(missing['stop_symbol'] == '_panic' and missing['argument_memory']['x0'].startswith('offline owner SystemOS mount failed: %d') and
        struct.unpack_from('<Q', bytes.fromhex(missing['stack_bytes']))[0] == 80 and
        state['_native_owner_cache_stage'] == 1 and state['_native_owner_cache_status'] == 80 and
        state['_native_owner_cache_mount_status'] == -1 and state['_native_owner_cache_selected_device'] == -1 and
        state['_native_owner_cache_mounted_device'] == -1 and state['_native_owner_cache_authorized'] == 0 and
        state['_native_owner_cache_root_recheck'] == 1 and missing['native_virtio_integrity']['_native_virtio_verified_devices'] == 1,
        'Missing authenticated SystemOS must actually stop startup before mount; no substitute/fallback')
require(any(e['number'] == 5 and e.get('path') == '/private/preboot/System/Library/Caches/com.apple.dyld'
            for e in continuation['syscall_events']) and any(e['number'] == 6 and int(e['arguments'][0], 16) == 0
            for e in continuation['syscall_events']), 'Observe genuine override-directory request and later descriptor-0 close')
require(file_call['stop_symbol'] == '_openat' and file_call['function_return_stack_matched'] and int(file_call['x0'], 16) == 9 and
        bytes.fromhex(file_call['entry_indirect_memory']['1:8:100']['bytes']).split(b'\0')[0] == b'dyld_shared_cache_arm64' and
        file_call['entry_indirect_memory']['1:8:100']['address_space'] == 'user', 'Actual original cache basename returns EBADF=9, not a guessed architecture/file-name failure')
require(continuation['fatal_user_exit']['namespace'] == 6 and 'no dyld cache' in continuation['fatal_user_exit']['description'], 'Preserve genuine later dyld refusal')
print('PASS: actual signed SystemOS mounts read-only under the real original OS root; absent volume genuinely stops startup')
print('PASS: original dyld requests correct arm64 cache name; genuine openat returns EBADF after ignition descriptor cleanup')
print('Full cache mapping, launchd main, firmware enrollment and sheng hardware remain open')
