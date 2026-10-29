#!/usr/bin/env python3
"""Qualify owner image-set metadata, original boot tasks and a genuine Data write refusal."""
import hashlib
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]
base = runpy.run_path(str(ROOT / 'scripts/check-original-launchd-main-checkpoints.py'))
require = base['require']
expected = base['candidate']('native-owner-boot-manifest-candidate',
    'c8718350684b5041ccb639c84c3b55296b7d92e5a893186afa589e323bb6d15c',
    '4b9ae2ac623da3cca0cc11733775508f841e8acfeefedfa3258b2c88ad64f93a')

domain = b'VerifiedRoot.OwnerBootSet.v1\0'
parts = []
for name, role, size, digest in (
    ('os', 1, 47481664, 'fd86b95b7033e352843f98d1204ade29459bf608a7e1ccb1a9b04ac93533292eb39de7c334ebe98b43d0db470fa16e77'),
    ('systemos', 2, 25805344, '13148bb42c8ce4b56d835d89f91a4cea1ac0482111dc34a00cfddfee36037ce504923baae4bae2bae6da7d8229c53e54')):
    data = (ROOT / ('build/verified-root-' + name) / 'manifest.bin').read_bytes()
    require(len(data) == size and hashlib.sha384(data).hexdigest() == digest, 'Require exact original signed manifests, no padded/key bytes')
    parts.append(bytes([role]) + hashlib.sha384(data).digest())
digest = hashlib.sha384(domain + b''.join(parts)).hexdigest()
require(digest == '4787d7d9d6900c21e7fdd7b2192a932648aa024d158d1e0250c15a29d710ff7eca70dad2819ede499301dec31d10ba61', 'Canonical role/domain encoding')
positive, output, symlink, conflict = [base['report']('owner-hvf-' + name) for name in
    ('boot-manifest', 'boot-manifest-output', 'tzinit-symlink', 'boot-manifest-conflict')]
for d in (positive, output, symlink, conflict):
    require(d['kernel_sha256'] == expected and d['qemu_accelerator'] == 'hvf' and not d['bounded_timeout_interrupted'] and
            d['trust_cache_bundle_sha256'] == hashlib.sha256(base['trust']).hexdigest(), 'Require exact bounded candidate and unchanged original trust')
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and r['SCTLR_EL1'] & 1 and
            r['TTBR0_EL1'] and r['TTBR1_EL1'] and d['kernel_page_globals'] ==
            dict(_PAGE_SHIFT_CONST=12, _page_shift=12, _page_shift_user32=12, _page_size=4096), 'Actual MMU/runtime must remain native 4K')
    require(d['owner_root_binding_audit']['boot_root_accepted'] and d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80 and
            d['original_amfi_table_owner_observed'] and d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'] and
            d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
            d['native_virtio_globals']['_native_virtio_read_failures'] == 0 and d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0,
            'Preserve original AMFI/crypto, actual owner root and real disk/signature failures')
for d in (positive, output, symlink):
    require(d['owner_boot_manifest']['status'] == 0 and d['owner_boot_manifest']['sha384'] == digest and
            not d['owner_boot_manifest']['firmware_personalization'] and not d['owner_boot_manifest'].get('conflicting_untrusted_dt_input', False),
            'Real kernel publication/readback must match exact authenticated host envelopes in the owner domain')
    require(d['owner_cache_mount']['_native_owner_cache_status'] == 0 and
            d['native_signature_hash_cache']['_cs_native4k_full_blocks'] == 201083 and
            d['native_signature_hash_cache']['_cs_native4k_ready_blobs'] == 53 and
            d['native_signature_hash_cache']['_cs_native4k_page_checks'] > 2000, 'Original complete cache must still pass genuine validation')
for d in (positive, output):
    require(d['critical_process_exit'] == dict(process='tzinit[17] exited', signal=0, status=30, cs_status=''), 'Preserve the real later timezone failure')
writes = [bytes.fromhex(e['write_bytes']).decode(errors='replace') for e in output['syscall_events']
          if e['number'] in (4, 397) and 'write_bytes' in e and not e['write_bytes'].startswith('E')]
for text in ('(mount-phase-1)', '(data-protection)', '(mount-phase-2)', '(init-with-data-volume)',
             '(fips)', 'all tests PASSED', 'result = true', '(keybag)', 'FATAL KEYBAG ERROR', '(usermanagerd)'):
    require(any(text in x for x in writes), 'Require actual original boot output: ' + text)
require(any(digest.upper() in x and '/private/preboot/' in x for x in writes) and
        not any('failed to get boot-manifest-hash' in x for x in writes) and
        any(e['number'] == 1 and int(e['arguments'][0], 16) == 0 for e in output['syscall_events']), 'Original consumers use the owner hash and earlier boot children exit zero')
require(symlink['stop_symbol'] == '_symlink' and symlink['function_return_stack_matched'] and int(symlink['x0'], 16) == 30 and
        symlink['entry_string_events'][-1]['matched'] and symlink['entry_string_events'][-1]['value'] == '/var/db/timezone/zoneinfo', 'Actual selected timezone symlink returns EROFS on the same stack')
for request, path in [('1:0:80', '/usr/share/zoneinfo.default'), ('1:8:80', '/var/db/timezone/zoneinfo')]:
    require(bytes.fromhex(symlink['entry_indirect_memory'][request]['bytes']).split(b'\0')[0].decode() == path, 'Actual syscall target/link arguments')
require(conflict['owner_boot_manifest']['conflicting_untrusted_dt_input'] and conflict['owner_boot_manifest']['status'] == 3 and
        conflict['owner_boot_manifest']['sha384'] == '00' * 48 and
        conflict['owner_cache_mount']['_native_owner_cache_status'] == 80 and
        conflict['native_signature_hash_cache']['_cs_native4k_page_checks'] == 0, 'An existing untrusted identity must cause real startup refusal before userspace')
print('PASS: authenticated owner image-set SHA-384 matches real kernel publication/readback; conflicting identity refuses startup')
print('PASS: original mount phases and userspace corecrypto FIPS POST complete; actual timezone symlink returns EROFS')
print('Writable Data/keybags, firmware enrollment, functional iPadOS UI and sheng hardware remain open')
