#!/usr/bin/env python3
"""Verify unchanged target cache data through real native-4K file APIs in QEMU."""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
build = ROOT / 'build'
fixture = build / 'native-cache-file-fixture'
metadata = json.loads((fixture / 'file-probe.json').read_text())
candidate = json.loads((build / 'xnu-prelink/native-readonly-file-candidate.json').read_text())


def require(value, message):
    if not value:
        raise SystemExit('FAIL: ' + message)


image = (fixture / 'root.img').read_bytes()
magic, version, count, own_at, own_size, file_at, file_size = struct.unpack_from('<8sII4Q', image)
require((magic, version, count) == (b'N4KROOT\0', 1, 2), 'offline input format')
own = image[own_at:own_at + own_size]
target = image[file_at:file_at + file_size]
require(own == (fixture / 'launchd.macho').read_bytes(), 'unchanged own process')
require(hashlib.sha256(target).hexdigest() == metadata['original_file_sha256'] ==
        '3d923c404fe519184a99042b60a4cb3d37247dcb8b070242ed3e670d4d523d04', 'exact supplied target file')
require(hashlib.sha256(image).hexdigest() == metadata['root_sha256'], 'input container identity')
trust = json.loads((fixture / 'offline-file-trust.json').read_text())
own_trust = json.loads((fixture / 'trustcache.json').read_text())
require(trust['cdhashes'] == sorted((metadata['original_cdhash'], own_trust['cdhash'])) and
        not trust['apple_trust_chain_verified'] and not trust['original_apple_trust_cache_modified'],
        'explicit offline trust scope')


def report(name, direct=False, own_sha=metadata['own_process_sha256']):
    d = json.loads((build / name / 'gdb-stop.json').read_text())
    require(d['kernel_sha256'] == candidate['candidate_sha256'], 'same exact source/component candidate')
    require(not d['bounded_timeout_interrupted'], name + ': no timeout inference')
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'], 'actual native 4K MMU')
    if not direct:
        require(d['original_amfi_table_owner_observed'] and d['original_crypto_initialized_observed'],
                'original security providers')
        require(d['native_user_el0_observed'] and d['native_user_4k_abi_observed'] and
                not d['ipados_userspace_boot_demonstrated'], 'own process ABI and scope')
        require(d['native_user_image_sha256'] == own_sha, 'own process identity')
    return d


refusal = report('darwinboot-original-cache-readonly-file')
require(refusal['offline_root_sha256'] == metadata['root_sha256'] and
        refusal['trust_cache_bundle_sha256'] == own_trust['bundle_sha256'], 'own-only trust control')
f = refusal['native_file_probe']
require(f['open_result'] == 0 and f['open_nzcv'] >> 29 & 1 == 0 and f['stage'] == 1 and
        f['fcntl_result'] == 1 and f['fcntl_nzcv'] >> 29 & 1 == 1, 'real registration EPERM control')
require(refusal['native_signature_hash_cache']['_cs_native4k_ready_blobs'] == 0, 'no untrusted publication')

positive = report('darwinboot-original-cache-owner-trust')
require(positive['offline_root_sha256'] == metadata['root_sha256'] and
        positive['trust_cache_bundle_sha256'] == trust['bundle_sha256'], 'explicit file-test trust')
f = positive['native_file_probe']
require(f['stage'] == 4 and f['open_result'] == 0 and f['fcntl_result'] == 0 and f['mmap_result'] != 0,
        'genuine open/signature registration/mmap completed')
require(not any(f[n] >> 29 & 1 for n in ('open_nzcv', 'fcntl_nzcv', 'mmap_nzcv')), 'no file syscall errors')
require(f['signature_end'] == metadata['code_limit'] and f['native_pages_read'] == 8 and
        f['page_word_xor'] == metadata['expected_page_word_xor'], 'actual original page reads')
c = positive['native_signature_hash_cache']
require((c['_cs_native4k_full_blocks'], c['_cs_native4k_page_checks'], c['_cs_native4k_ready_blobs']) ==
        (2, 8, 1), 'two original signing blocks and eight actual native page checks')
require(set(positive['code_signing_hash_counters'].values()) == {0}, 'no missing/bad page hashes')

inspection = report('darwinboot-original-cache-guest-signature', direct=True)
require(int(inspection['x0'], 16) == 0 and inspection['skipped_target_hits'] == 1, 'actual second blob authentication')
captured = inspection['entry_indirect_memory']
cd = bytes.fromhex(captured['1:80:200']['bytes'])
length = struct.unpack_from('>I', cd, 4)[0]
require(length <= len(cd) and cd[39] == 14 and hashlib.sha256(cd[:length]).hexdigest()[:40] ==
        metadata['original_cdhash'], 'unchanged actual guest target CodeDirectory/CDHash')
cache = captured['1:b8:1000']
digests = bytes.fromhex(cache['bytes'])
expected = b''.join(hashlib.sha256(target[o:o + 4096]).digest() for o in range(0, metadata['code_limit'], 4096))
require(digests[:len(expected)] == expected and not any(digests[len(expected):]), 'actual target derived hashes/padding')
t = cache['translation']
require(t['leaf_level'] == 3 and t['leaf_bytes'] == 4096 and t['ap'] == 2 and t['pxn'] and t['uxn'],
        'actual target digest mapping read-only/NX/native4K')

negative = report('darwinboot-original-cache-bad-native-page')
bad = bytearray(image)
bad[file_at + 4096] ^= 1
require(hashlib.sha256(bad).hexdigest() == negative['offline_root_sha256'] and
        negative['trust_cache_bundle_sha256'] == trust['bundle_sha256'], 'one-bit corruption, unchanged trust')
f = negative['native_file_probe']
require(f['stage'] == 1 and f['fcntl_result'] == 85 and f['fcntl_nzcv'] >> 29 & 1 == 1 and
        f['native_pages_read'] == 0, 'real EBADEXEC before mapping corrupted target file')
require(negative['code_signing_hash_counters']['_cs_validate_page_bad_hash'] == 1 and
        negative['native_signature_hash_cache']['_cs_native4k_ready_blobs'] == 0, 'original target hash enforced')

legacy = report('darwinboot-two-file-legacy-root-regression',
                own_sha='8e6cb80348e018c780e3a8b71bed6015e80e932b23be378bfcdd67846277b9a0')
malformed = report('darwinboot-two-file-malformed-root', direct=True)
require(int(malformed['x0'], 16) == 22 and malformed.get('finished_function_entry'),
        'overlapping malformed root returns EINVAL through actual mount function cleanup')

result = dict(candidate_sha256=candidate['candidate_sha256'], original_file_sha256=metadata['original_file_sha256'],
              original_cdhash=metadata['original_cdhash'], original_file_bytes_modified=False,
              original_hash_blocks_authenticated=2, native_4k_pages_checked=8, checkpoints=6,
              explicit_offline_file_trust=True, apple_boot_trust_chain_verified=False,
              target_component_code_executed=False, target_ipados_booted=False, sheng_hardware_tested=False)
(build / 'original-cache-file-checkpoints.json').write_text(json.dumps(result, indent=2) + '\n')
print('PASS: unchanged original cache file; real registration, native-4K mappings/faults and corruption refusal')
print('Explicit offline file trust; no original target code execution, iPadOS boot or hardware claim')
