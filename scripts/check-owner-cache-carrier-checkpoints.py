#!/usr/bin/env python3
"""Qualify independent owner cache carrier mapping and preserve original downstream refusals."""
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


original = (ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed').read_bytes()
require(hashlib.sha256(original).hexdigest() == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7', 'Require supplied target')
trust = (ROOT / 'build/original-static-system-trust/original-static-system.bundle').read_bytes()
require(hashlib.sha256(trust).hexdigest() == '7416ca4f8377146626bb284e2133c76bee6cb4e3ee0af5d648b186235a7323a7' and
        struct.unpack_from('<II', trust) == (2, 12), 'Require only the two original trust modules')
second = struct.unpack_from('<I', trust, 8)[0]
require(hashlib.sha256(trust[12:second]).hexdigest() == 'da88460e6e513438d5307e5c526f76497a74754476a24da29f239f0c90120fc2' and
        hashlib.sha256(trust[second:]).hexdigest() == 'd121ba89167e03aafd00fa687c30cd8ebc4ccafd10c1408adb2ba3de12403651',
        'No original trust byte or own code entry may be substituted')

def candidate(name, native_hash, image_hash):
    stem = ROOT / 'build/xnu-prelink' / name
    plan = json.loads(stem.with_suffix('.json').read_text())
    data = stem.with_suffix('.macho').read_bytes()
    require(hashlib.sha256(data).hexdigest() == plan['candidate_sha256'] == image_hash and
            plan['native_sha256'] == native_hash and len(plan['components']) == 15, 'Require exact owner carrier candidate')
    src, dst = np.macho(original), np.macho(data)
    for e in plan['extents']:
        if e['segment'] != '__TEXT_EXEC': continue
        a = np.backed_offset(dst['segments'], e['va'], e['size'], len(data))
        b = np.backed_offset(src['segments'], e['va'] - plan['slide'], e['size'], len(original))
        require(data[a:a + e['size']] == original[b:b + e['size']], 'Every original executable extent remains unchanged')
    return image_hash


good_hash = candidate('native-owner-cache-carrier-candidate',
    '857cacf032b318fbacbcd9ce6c3a14ea74dabdea3e14c2024e62f35267de9ff3',
    '6bd06ccef04dc3e740ac58ace78eb17437e3bdf41ba8891af92f605c80a97320')
bad_hash = candidate('native-owner-carrier-wrong-uuid-candidate',
    '8947c255cc64dc7b0465fcb5695bd8317e74e7deddd25bdc8cc92f4950dd0d0d',
    '4450ace690a97125eb509cd129588eac72951f5e939d74531f15aedf8d3870cd')
positive, negative, continuation, missing_policy = [report(name) for name in (
    'owner-hvf-carrier-shared-region', 'owner-hvf-carrier-wrong-uuid',
    'owner-hvf-original-continuation', 'owner-hvf-sandbox-policy')]
for d, expected in ((positive, good_hash), (negative, bad_hash), (continuation, good_hash), (missing_policy, good_hash)):
    require(d['kernel_sha256'] == expected and d['qemu_accelerator'] == 'hvf' and
            not d['bounded_timeout_interrupted'] and d['trust_cache_bundle_sha256'] == hashlib.sha256(trust).hexdigest(), 'Exact bounded HVF and original trust input')
    regs = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(regs['TCR_EL1'] >> 14 & 3 == 0 and regs['TCR_EL1'] >> 30 & 3 == 2 and regs['SCTLR_EL1'] & 1 and
            regs['TTBR0_EL1'] and regs['TTBR1_EL1'] and d['commpage_user64_shifts'] ==
            dict(_commpage_rw_addr=12, _commpage_kernel_ro_addr=12), 'Actual native-4K mappings and commpage shift data')
    require(d['actual_physical_memory']['_gPhysSize'] == 0x20000000 and d['actual_physical_memory']['_mem_actual'] == 0x20000000 and
            d['original_amfi_table_owner_observed'] and d['original_crypto_initialized_observed'] and
            d['original_crypto_table_owner_observed'] and d['owner_root_binding_audit']['boot_root_accepted'] and
            d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80, 'Real owned memory and owner proof retain original AMFI/crypto')
    require(d['native_virtio_globals']['_native_virtio_read_failures'] == 0 and
            d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0 and
            d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0), 'No unauthenticated I/O or invalid code pages')
for d, status, checks, accepts, rejects in ((positive, 0, 254, 53, 0), (negative, 1, 212, 0, 1)):
    require(d['stop_symbol'] == '_shared_region_map_and_slide_2_np' and d['function_return_stack_matched'] and
            int(d['x0'], 16) == status and d['pc'] == d['function_return_target'], 'Actual same-stack shared-region result')
    carrier = d['owner_cache_carrier']
    require(carrier['_native_owner_cache_carrier_accepts'] == accepts and carrier['_native_owner_cache_carrier_rejects'] == rejects and
            carrier['_native_owner_cache_carrier_root_device'] == 0x01000006 and carrier['_native_owner_cache_carrier_file_device'] == 0x01000004,
            'Actual OS/SystemOS mounted devices must pass only the expected signed UUID')
    require(d['native_signature_hash_cache'] == dict(_cs_native4k_hash_cache_version=1, _cs_native4k_full_blocks=201083,
            _cs_native4k_page_checks=checks, _cs_native4k_ready_blobs=53), 'Retain complete original preflight and native-page checks')
policies = {positive['native_virtio_integrity'][name] for name in (
    '_native_virtio_verified_manifest_pointer', '_native_virtio_verified_key_pointer')}
observed = set()
for capture in positive['indirect_memory'].values():
    pointer = int(capture['pointer'], 16)
    if pointer not in policies: continue
    t = capture['translation']
    require(t['leaf_level'] == 3 and t['leaf_bytes'] == 4096 and t['ap'] == 2 and t['pxn'] and t['uxn'], 'Actual private policy/key copies retain native-4K RO/NX leaves')
    observed.add(pointer)
require(observed == policies and len(policies) == 2, 'Observe both real private policy and key mappings')
require(not positive['cstring_events'] and any("not on process' root volume nor preboot volume" in e['value'] for e in negative['cstring_events']),
        'Wrong expected UUID must preserve the actual original carrier refusal')
require(continuation['stop_symbol'] == '_panic_with_options' and continuation['fatal_user_exit'] ==
        dict(cs_status='', prefix='initproc failed to start', namespace=7, code=1,
             description='_container_init(): sandbox_get_container_expected() failed: %d') and
        continuation['native_signature_hash_cache']['_cs_native4k_page_checks'] == 1392,
        'Preserve the actual subsequent original system-library initialization refusal')
require(missing_policy['stop_symbol'] == '___mac_syscall' and missing_policy['function_return_stack_matched'] and
        int(missing_policy['x0'], 16) == 103 and missing_policy['entry_string_events'][-1]['matched'] and
        missing_policy['entry_string_events'][-1]['value'] == 'Sandbox' and
        bytes.fromhex(missing_policy['entry_indirect_memory']['1:0:40']['bytes']).startswith(b'Sandbox\0'),
        'Actual selected Sandbox request genuinely returns ENOPOLICY=103; no handler is fabricated')
print('PASS: actual owner-authorized 53-file shared-region mapping returns 0 at native 4K; wrong UUID still returns EPERM')
print('PASS: actual private policy/key RO/NX 4K PTEs; original system library runs until genuine missing Sandbox policy')
print('Launchd main, full iPadOS UI, firmware enrollment and bare-metal PMGR remain open')
