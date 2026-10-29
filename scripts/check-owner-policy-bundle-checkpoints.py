#!/usr/bin/env python3
"""Qualify independent signed policies per device and real ambiguity refusal."""
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


original = (ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed').read_bytes()
require(hashlib.sha256(original).hexdigest() == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7', 'Require supplied target')
old = np.macho(original)
os_policy = (ROOT / 'build/verified-root-os/manifest.bin').read_bytes()
system_policy = (ROOT / 'build/verified-root-systemos/manifest.bin').read_bytes()
key = (ROOT / 'build/verified-root-os/trusted-key.bin').read_bytes()
cases = (
    ('darwinboot-owner-two-verified-devices', 'native-owner-policy-bundle-candidate', '1623845aad68c0c2c31d29c1d7047be900be26071c364d5826d213ed536da170', 2),
    ('darwinboot-owner-policy-ambiguity-refusal', 'native-owner-policy-ambiguous-candidate', 'ce61f3a8723834292485e95c5f8c0ca96697d282486f12b0c7def50f51cba700', 3),
)
reports = []
for directory, name, identity, count in cases:
    d = json.loads((ROOT / 'build' / directory / 'gdb-stop.json').read_text())
    reports.append(d)
    plan = json.loads((ROOT / 'build/xnu-prelink' / (name + '.json')).read_text())
    data = (ROOT / 'build/xnu-prelink' / (name + '.macho')).read_bytes()
    meta = np.macho(data)
    exports = np.exports(data, meta)
    symbols = {name: address for address, names in exports.items() for name in names}
    require(d['kernel_sha256'] == plan['candidate_sha256'] == hashlib.sha256(data).hexdigest() == identity and
            not d['bounded_timeout_interrupted'] and len(plan['components']) == 15, 'Require exact bounded original-component candidates')

    def read(address, length):
        at = np.backed_offset(meta['segments'], address, length, len(data))
        return data[at:at + length]

    require(struct.unpack('<Q', read(symbols['_verified_root_policy_count'], 8))[0] == count and
            read(symbols['_verified_root_key'], len(key)) == key, 'Require explicit same independently supplied anchor and bundle count')
    records = struct.unpack('<' + 'QQ' * count, read(symbols['_verified_root_policies'], count * 16))
    wanted = [os_policy, system_policy] + ([os_policy] if count == 3 else [])
    for index, policy in enumerate(wanted):
        address, length = records[index * 2:index * 2 + 2]
        require(length == len(policy) and read(address, length) == policy, 'Both bundles retain exact original signed policies; duplicate control changes only selection ambiguity')
    for e in plan['extents']:
        if e['segment'] == '__TEXT_EXEC':
            at = np.backed_offset(old['segments'], e['va'] - plan['slide'], e['size'], len(original))
            require(read(e['va'], e['size']) == original[at:at + e['size']], 'Every original executable byte must remain unchanged')
    regs = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(regs['TCR_EL1'] >> 14 & 3 == 0 and regs['TCR_EL1'] >> 30 & 3 == 2 and regs['SCTLR_EL1'] & 1 and
            regs['TTBR0_EL1'] and regs['TTBR1_EL1'] and d['original_crypto_initialized_observed'] and
            d['original_crypto_table_owner_observed'] and d['function_return_stack_matched'], 'Require actual native-4K return and real crypto provider')

d, refusal = reports
state, io, integrity = d['owner_root_binding_audit'], d['native_virtio_globals'], d['native_virtio_integrity']
require(d['stop_symbol'] == '_native_owner_root_accepted_checkpoint' and state['boot_root_accepted'] and
        state['_native_owner_root_apple_autherr'] == 80 and state['_native_owner_root_mount_device'] ==
        state['_native_owner_root_selected_device'] == state['_native_verified_block_root_device'] == 0x01000006 and
        state['actual_uuid'] == '04769D26-2CA0-4825-B443-E2E5F88300F2' and state['_native_verified_block_root_media_matches'] == 1 and
        state['_native_verified_block_root_uuid_match'] == 1 and d['original_amfi_table_owner_observed'], 'Root binding must follow actual media despite changed device enumeration')
require(d['virtio_block_input']['read_only'] and d['virtio_block_input']['bytes'] == 6077580800 and
        d['virtio_extra_block_input']['read_only'] and d['virtio_extra_block_input']['bytes'] == 3303014400 and
        d['virtio_extra_block_input']['first_sector_sha256'] ==
        '42b1178767bb27611cd1836cdd5779c48bfca8a3e719ec06dc4c8ef78d5e6387', 'Require both actual unchanged read-only backends')
require(integrity['_native_virtio_verified_devices'] == 2 and integrity['_native_virtio_ambiguous_policies'] == 0 and
        integrity['_native_virtio_verified_blocks'] == 391 and integrity['_native_virtio_integrity_failures'] == 0 and
        io['_native_virtio_read_requests'] == 229 and io['_native_virtio_read_failures'] == 0, 'Each device must independently authenticate before readiness, with actual protected reads')
copies = list(d['indirect_memory'].values())
require(len(copies) == 2 and any(bytes.fromhex(v['bytes']) == system_policy[:32] for v in copies) and
        any(bytes.fromhex(v['bytes']) == key[:32] for v in copies), 'Observe actual second-device policy and independent key copies')
for value in copies:
    t = value['translation']
    require(t['leaf_level'] == 3 and t['leaf_bytes'] == 4096 and t['ap'] == 2 and t['pxn'] and t['uxn'], 'Actual per-device private policy/key pages must be RO/NX native-4K leaves')
integrity, io = refusal['native_virtio_integrity'], refusal['native_virtio_globals']
require(refusal['stop_symbol'] == '__ZN17NativeVirtioBlock21configureVerificationEv' and int(refusal['x0'], 16) == 0 and
        integrity['_native_virtio_ambiguous_policies'] == 1 and integrity['_native_virtio_verified_devices'] == 0 and
        integrity['_native_virtio_manifest_ready'] == 0 and integrity['_native_virtio_verified_blocks'] == 0 and
        integrity['_native_virtio_verified_manifest_pointer'] == 0 and integrity['_native_virtio_verified_key_pointer'] == 0 and
        io['_native_virtio_ready'] == 0 and io['_native_virtio_read_requests'] == 0 and not refusal['indirect_memory'],
        'A genuine duplicated policy must return false before allocation, DMA or media publication')
abi = json.loads((ROOT / 'build/virtio-mmio-block-verified-bundle/bindings.json').read_text())
require(abi['virtual_methods_checked'] == 190 and abi['concrete_overrides'] == 25 and abi['unresolved_original_imports'] == 0, 'Concrete storage ABI must remain intact')
print('PASS: both original media independently authenticate and read; actual OS root remains bound to its signed UUID')
print('PASS: identical duplicated signed policy refuses before private allocation, DMA or readiness')
print('This qualifies two protected devices, not SystemCryptex mounting, full shared-cache loading or hardware boot')
