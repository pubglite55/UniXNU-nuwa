#!/usr/bin/env python3
"""Qualify original Sandbox policy and original launchd LC_MAIN execution at native 4K."""
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
            plan['native_sha256'] == native_hash and len(plan['components']) == 17 and 'com.apple.security.sandbox' in plan['components'] and
            'com.apple.kext.AppleMatch' in plan['components'], 'Require exact owner carrier candidate')
    src, dst = np.macho(original), np.macho(data)
    for e in plan['extents']:
        if e['segment'] != '__TEXT_EXEC': continue
        a = np.backed_offset(dst['segments'], e['va'], e['size'], len(data))
        b = np.backed_offset(src['segments'], e['va'] - plan['slide'], e['size'], len(original))
        require(data[a:a + e['size']] == original[b:b + e['size']], 'Every original executable extent remains unchanged')
    return image_hash


expected = candidate('native-owner-sandbox-candidate',
    'ed9ffce9c5101a3881fd02287d5c88d1a3c2df7cd1cb6b0d00f84795916c76b8',
    '93b50849a857f21410fbe2f5dc6ddcf732ed61a06a42be6e95b9e99f9d6ba959')
policy, main, continuation = [report(name) for name in (
    'owner-hvf-sandbox-policy-present', 'owner-hvf-launchd-main', 'owner-hvf-original-sandbox')]
for d in (policy, main, continuation):
    require(d['kernel_sha256'] == expected and d['qemu_accelerator'] == 'hvf' and not d['bounded_timeout_interrupted'] and
            d['trust_cache_bundle_sha256'] == hashlib.sha256(trust).hexdigest(), 'Exact bounded original Sandbox closure and unchanged trust input')
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and r['SCTLR_EL1'] & 1 and
            r['TTBR0_EL1'] and r['TTBR1_EL1'] and d['kernel_page_globals'] ==
            dict(_PAGE_SHIFT_CONST=12, _page_shift=12, _page_shift_user32=12, _page_size=4096), 'Actual hardware and kernel runtime remain native 4K')
    require(d['original_amfi_table_owner_observed'] and d['original_crypto_initialized_observed'] and
            d['original_crypto_table_owner_observed'] and d['owner_root_binding_audit']['boot_root_accepted'] and
            d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80 and
            d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0), 'Original AMFI/crypto, owner root and code validation remain genuine')
    require(d['native_virtio_globals']['_native_virtio_read_failures'] == 0 and
            d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0, 'Keep actual media integrity')
require(policy['stop_symbol'] == '___mac_syscall' and policy['function_return_stack_matched'] and int(policy['x0'], 16) == 0 and
        policy['entry_string_events'][-1]['value'] == 'Sandbox' and policy['entry_string_events'][-1]['matched'] and
        bytes.fromhex(policy['entry_indirect_memory']['1:0:40']['bytes']).startswith(b'Sandbox\0'), 'Original registered Sandbox handler really accepts the selected request')
launchd = (ROOT / '.cache/firmware/target-volumes/os-mount/sbin/launchd').read_bytes()
require(hashlib.sha256(launchd).hexdigest() == main['original_launchd_main_input']['sha256'] ==
        '8cec9a3c44a443b08e977ccc5d577850316ad428c575dc01f09b018dbd5b6a25', 'Require unchanged supplied ARM64 launchd')
m = main['followed_main_entry']
header = int(m['mach_header'], 16)
require(main['original_launchd_main_executed'] and main['stop_symbol'] == 'original-launchd-main' and
        m['observed'] and m['first_instruction_completed'] and m['entry_offset'] == 85896 and
        int(m['pc'], 16) == header + 85896 and int(m['checkpoint_pc'], 16) == int(main['pc'], 16) == header + 85900 and
        int(m['pstate'], 16) & 15 == int(m['checkpoint_pstate'], 16) & 15 == int(main['pstate'], 16) & 15 == 0 and
        m['entry_bytes_after_fault'] == launchd[85896:85912].hex() and m['mach_header_bytes'] == launchd[:32].hex(),
        'Actual original LC_MAIN and completed first instruction must match the original bytes at EL0')
require(struct.unpack('<2Q', bytes.fromhex(m['startup_stack_bytes'])) == (header, 1) and
        m['argc_on_startup_stack'] == 1 and int(m['arguments'][0], 16) == 1 and
        main['direct_user_commpage_shifts'] == {'fffff4025:1': 12, 'fffff4037:1': 12}, 'Follow actual dyld startup stack and real user commpage values, no guessed ASLR or ABI')
require(main['native_signature_hash_cache'] == dict(_cs_native4k_hash_cache_version=1, _cs_native4k_full_blocks=201083,
        _cs_native4k_page_checks=1543, _cs_native4k_ready_blobs=53) and
        main['owner_cache_carrier']['_native_owner_cache_carrier_accepts'] == 53 and
        main['owner_cache_carrier']['_native_owner_cache_carrier_rejects'] == 0, 'Real original cache is authenticated and used through native-4K faults')
require(continuation['stop_symbol'] == '_panic_with_options' and continuation['panic_with_options']['format'].startswith('%s -- no exit reason available'), 'Preserve later real critical-process exit')
args = struct.unpack_from('<4Q', bytes.fromhex(continuation['stack_bytes']))
raw_name = continuation['stack_pointer_memory']['0']['bytes']
require(bytes.fromhex(raw_name).split(b'\0')[0] == b'mount[3] exited' and args[1] == 0 and args[2] == 66 and
        bytes.fromhex(continuation['stack_pointer_memory']['3']['bytes']).split(b'\0')[0] == b'' and
        continuation['native_signature_hash_cache']['_cs_native4k_page_checks'] == 2187,
        'Actual mount child exits 66 normally; do not mislabel this as an initproc code-sign kill')
print('PASS: unchanged original Sandbox policy is active; unchanged original launchd starts LC_MAIN at native-4K EL0')
print('PASS: actual first main instruction, original bytes, user shifts 12/12 and genuine later mount-child status 66')
print('Functional iPadOS UI, writable Data integration, firmware enrollment and sheng hardware remain open')
