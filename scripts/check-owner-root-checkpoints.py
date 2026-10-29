#!/usr/bin/env python3
"""Qualify actual owner root enforcement and independent identity refusal."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
import native_prelink as np


def require(value, message):
    if not value:
        raise SystemExit(message)


original = (ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed').read_bytes()
require(hashlib.sha256(original).hexdigest() == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7',
        'Require the supplied ordinary-ARM64 target')
old = np.macho(original)
policy = (ROOT / 'build/verified-root-os/manifest.bin').read_bytes()
wrong_policy = (ROOT / 'build/verified-root-os-xnu-wrong-uuid/wrong-uuid-manifest.bin').read_bytes()
anchor = (ROOT / 'build/verified-root-os/trusted-key.bin').read_bytes()
require(policy[544:] == wrong_policy[544:] and policy[:40] == wrong_policy[:40] and policy[56:160] == wrong_policy[56:160] and
        policy[40:56] != wrong_policy[40:56], 'Negative policy changes only signed UUID/signature, preserving every original hash')
require(str(uuid.UUID(bytes=policy[40:56])).upper() == '04769D26-2CA0-4825-B443-E2E5F88300F2' and
        struct.unpack_from('<QQ', policy, 24) == (6077580800, 1483785), 'Require complete exact original OS media policy')
host = json.loads((ROOT / 'build/verified-root-os/verification.json').read_text())
require(host['real_c_signature_and_block_verification'] and host['blocks_verified'] == 1483785 and
        host['image_sha256'] == 'e5634d04a8ac35f024845f583394e0a35deb26a04cb0c00286a8674e25a9a4f2',
        'Require separate complete original host data verification')

cases = (
    ('default-refusal', 'native-owner-root-trust-default-candidate', 'aca84655e63702d77ea0be2004c8ccc74bb3f334597906aed08eb9621a50cfaa', 0, 1, 0),
    ('accepted', 'native-owner-root-trust-candidate', 'bd231941e1ff79c2f1917f99c2e5f05720d5f0a1fdc3d325f732609cb9ecfd63', 1, 1, 1),
    ('wrong-uuid-refusal', 'native-owner-root-wrong-uuid-candidate', '4e719827eae5a48f73158991ff6d142f9baa4a7bd8994bdaea43d04bc416ff4e', 1, 0, 0),
    ('original-continuation', 'native-owner-root-trust-candidate', 'bd231941e1ff79c2f1917f99c2e5f05720d5f0a1fdc3d325f732609cb9ecfd63', 1, 1, 1),
)
reports = {}
for name, candidate, identity, enabled, decision, accepted in cases:
    d = json.loads((ROOT / ('build/darwinboot-owner-root-' + name) / 'gdb-stop.json').read_text())
    reports[name] = d
    plan = json.loads((ROOT / 'build/xnu-prelink' / (candidate + '.json')).read_text())
    kernel = (ROOT / 'build/xnu-prelink' / (candidate + '.macho')).read_bytes()
    require(d['kernel_sha256'] == plan['candidate_sha256'] == hashlib.sha256(kernel).hexdigest() == identity and
            not d['bounded_timeout_interrupted'] and len(plan['components']) == 14, 'Require exact bounded native candidates')
    meta = np.macho(kernel)
    exports = np.exports(kernel, meta)
    for symbol, wanted in (('_verified_root_manifest', wrong_policy if name == 'wrong-uuid-refusal' else policy),
                           ('_verified_root_key', anchor)):
        address = next(a for a, names in exports.items() if symbol in names)
        at = np.backed_offset(meta['segments'], address, len(wanted), len(kernel))
        require(kernel[at:at + len(wanted)] == wanted, 'Require the actual identical anchor and identified signed policy')
    for extent in plan['extents']:
        if extent['segment'] != '__TEXT_EXEC':
            continue
        at = np.backed_offset(meta['segments'], extent['va'], extent['size'], len(kernel))
        prev = np.backed_offset(old['segments'], extent['va'] - plan['slide'], extent['size'], len(original))
        require(kernel[at:at + extent['size']] == original[prev:prev + extent['size']], 'Original executable code must remain unchanged')
    regs = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(regs['TCR_EL1'] >> 14 & 3 == 0 and regs['TCR_EL1'] >> 30 & 3 == 2 and regs['SCTLR_EL1'] & 1 and
            regs['TTBR0_EL1'] and regs['TTBR1_EL1'], 'Require actual native hardware 4K, not source constants')
    require(d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'] and
            d['original_amfi_table_owner_observed'] and d['virtio_block_input']['read_only'], 'Original AMFI/crypto must remain active')
    state, io, integrity = d['owner_root_binding_audit'], d['native_virtio_globals'], d['native_virtio_integrity']
    require(state['_native_owner_root_apple_autherr'] == 80 and state['_native_owner_root_readonly'] == 1 and
            state['_native_owner_root_trust_enabled'] == enabled and state['_native_owner_root_decision'] == decision and
            state['_native_owner_root_accepted'] == accepted and state['boot_root_accepted'] == bool(accepted),
            'Actual enforcement must retain Apple EAUTH and independently require real owner proof')
    require(state['_native_owner_root_mount_device'] == state['_native_owner_root_selected_device'] ==
            state['_native_verified_block_root_device'] != 0 and state['_native_verified_block_root_media_matches'] == 1 and
            state['_native_verified_block_root_provider_depth'] == 9 and state['_native_verified_block_root_uuid_match'] == decision and
            state['_native_verified_block_wrong_uuid_refused'] == 1 and
            state['actual_uuid'] == '04769D26-2CA0-4825-B443-E2E5F88300F2', 'Require actual mounted dev_t, unique IOMedia and typed verified provider')
    require(io['_native_virtio_ready'] == 1 and io['_native_virtio_sectors'] == 11870275 and
            io['_native_virtio_read_requests'] >= 167 and io['_native_virtio_read_failures'] == 0 and
            integrity['_native_virtio_manifest_ready'] == 1 and integrity['_native_virtio_verified_blocks'] >= 329 and
            integrity['_native_virtio_integrity_failures'] == 0, 'Real signed policy and every consumed DMA snapshot must qualify')
    if name in ('accepted', 'wrong-uuid-refusal'):
        copies = list(d['indirect_memory'].values())
        require(len(copies) == 2, 'Require actual private policy/key copies')
        for copy in copies:
            t = copy['translation']
            require(t['leaf_level'] == 3 and t['leaf_bytes'] == 4096 and t['ap'] == 2 and t['pxn'] and t['uxn'],
                    'Actual policy/key copies must retain read-only NX native-4K PTEs')
    if not accepted:
        require(d['stop_symbol'] == '_panic' and d['argument_memory']['x0'].startswith('rootvp not authenticated after mounting'),
                'Default-off and genuine signed wrong-identity policies must reach actual enforcement refusal')

d = reports['accepted']
require(d['stop_symbol'] == '_native_owner_root_accepted_checkpoint' and d['function_return_stack_matched'] and
        [int(x, 16) for x in d['function_entry_arguments'][:2]] == [80, 1],
        'Observe actual same-stack control flow after enforcement, never a pre-enforcement intent flag')
d = reports['original-continuation']
require(d['stop_symbol'] == '_panic' and d['argument_memory']['x0'].startswith('Process 1 exec of %s failed, errno %d') and
        struct.unpack_from('<Q', bytes.fromhex(d['stack_bytes']), 8)[0] == 45 and
        bytes.fromhex(d['stack_pointer_memory']['0']['bytes']).split(b'\0')[0] == b'/sbin/launchd' and
        any(e['symbol'] == '_native_owner_root_accepted_checkpoint' for e in d['trace_events']),
        'Record genuine later original launchd exec ENOTSUP; do not report userspace success')
binding = json.loads((ROOT / 'build/virtio-mmio-block-verified/bindings.json').read_text())
require(binding['virtual_methods_checked'] == 190 and binding['concrete_overrides'] == 25 and
        binding['unresolved_original_imports'] == 0, 'Require real IOStorage dispatch ABI')
print('PASS: native-4K original OS root accepted only through real owner signature, verified I/O and mounted-media identity')
print('PASS: default-off policy and genuinely signed wrong-volume UUID both refuse at actual root enforcement')
print('Original AMFI/crypto/code remain active; subsequent original launchd exec returns ENOTSUP=45; hardware/UI remain open')
