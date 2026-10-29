#!/usr/bin/env python3
"""Qualify genuine original 16K-signed cache code and native-4K fault refusal."""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]


def require(value, message):
    if not value:
        raise SystemExit(message)


positive = json.loads((ROOT / 'build/darwinboot-original-cache-getuid-bytes/gdb-stop.json').read_text())
negative = json.loads((ROOT / 'build/darwinboot-original-cache-getuid-code-fault-applied/gdb-stop.json').read_text())
fixture = ROOT / 'build/native-cache-getuid-fixture'
metadata = json.loads((fixture / 'cache-leaf.json').read_text())
leaf = metadata['cache_leaf_input']
require(leaf['public_export'] == '_getuid' and leaf['library'] == '/usr/lib/system/libsystem_kernel.dylib' and
        leaf['signing_block_bytes'] == 16384 and leaf['file_sha256'] ==
        '3b8b3d970cfb6a0baf4c526230da7e59edb24a70cc319d4b2287012221916302', 'Require the actual original 16K-signed target cache')
require(hashlib.sha256((fixture / 'launchd.macho').read_bytes()).hexdigest() == metadata['own_process_sha256'],
        'Own fixture identity differs')
trust = (fixture / 'original-cache-trust.bundle').read_bytes()
require(hashlib.sha256(trust).hexdigest() == metadata['trust_bundle_sha256'], 'Explicit offline trust bundle differs')
count = struct.unpack_from('<I', trust)[0]
require(count == 3, 'Use the own module and both unchanged original modules')
offsets = struct.unpack_from('<3I', trust, 4)
modules = [trust[start:end] for start, end in zip(offsets, [*offsets[1:], len(trust)])]
require(hashlib.sha256(modules[1]).hexdigest() == 'da88460e6e513438d5307e5c526f76497a74754476a24da29f239f0c90120fc2' and
        hashlib.sha256(modules[2]).hexdigest() == 'd121ba89167e03aafd00fa687c30cd8ebc4ccafd10c1408adb2ba3de12403651',
        'Original trust modules must be unchanged')
require(bytes.fromhex(leaf['original_cdhash']) in [modules[2][i:i + 20] for i in range(24, len(modules[2]), 24)],
        'Actual original cache CodeDirectory must be present in its actual original System module')
for d in (positive, negative):
    require(not d['bounded_timeout_interrupted'] and d['kernel_sha256'] ==
            '8db7506164cb7772c6af3e8bd21b4a9ee3a951c5c611550deae923ed1558628f', 'Require the exact bounded native candidate')
    require(d['native_user_image_sha256'] == metadata['own_process_sha256'] and
            d['trust_cache_bundle_sha256'] == metadata['trust_bundle_sha256'], 'Positive and fault must use identical process/trust')
    regs = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(regs['TCR_EL1'] >> 14 & 3 == 0 and regs['TCR_EL1'] >> 30 & 3 == 2 and
            regs['SCTLR_EL1'] & 1 and regs['TTBR0_EL1'] and regs['TTBR1_EL1'], 'Active native 4K hardware translation is required')
    require(set(d['commpage_user64_shifts'].values()) == {12}, 'Both real commpages must retain shift 12')
    require(d['original_amfi_table_owner_observed'] and d['original_crypto_initialized_observed'],
            'Use genuine active AMFI/corecrypto')
    require(d['native_virtio_globals']['_native_virtio_read_requests'] == 1879 and
            d['native_virtio_globals']['_native_virtio_read_failures'] == 0 and d['virtio_block_input']['read_only'],
            'Actual original APFS reads must complete without failure')
    cache = d['native_signature_hash_cache']
    require(cache['_cs_native4k_full_blocks'] == 6562 and cache['_cs_native4k_ready_blobs'] == 2 and
            cache['_cs_native4k_page_checks'] == 4, 'Authenticate all 6559 original signing blocks plus the own process')
    require(not d['original_full_cache_loaded'] and not d['root_authentication_solved'],
            'This component test must not claim a full cache or production boot')
require(positive['original_cache_leaf_executed'] and positive['original_cache_leaf_result'] == 0 and
        positive['native_user_4k_abi_observed'], 'The actual public original function must return under the real 4K ABI')
entry = positive['followed_user_entry']
require(entry['entry_bytes_after_fault'] == leaf['function_bytes'][:32] and int(entry['pstate'], 16) & 15 == 0,
        'Read original instruction bytes after the genuine first fault at EL0')
require(entry['checkpoint']['observed'] and entry['checkpoint']['bytes'].startswith('c0035fd6') and
        entry['function_return']['observed'] and int(entry['function_return']['pstate'], 16) & 15 == 0,
        'Observe the real original success RET and caller return')
call = [e for e in positive['syscall_events'] if e['number'] == 24]
require(len(call) == 1 and int(call[0]['user_pc'], 16) == int(entry['user_entry'], 16) + 8 and
        call[0]['user_lr'] == entry['function_return']['target'], 'Original code must execute its own real getuid SVC')
require(positive['code_signing_hash_counters'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0),
        'Positive code faults must validate without missing hashes')
fault = negative['own_mapped_page_mutation']
require(fault['code_directory_hash'] == leaf['original_cdhash'] and
        fault['page_sha256_before'] == leaf['original_page_sha256'] and
        fault['file_page'] == leaf['native_page_offset'] and fault['byte_in_page'] == leaf['within_page_offset'] and
        fault['before'] ^ fault['after'] == 1 and not fault['registers_or_validation_state_modified'],
        'Mutate only the identity-qualified actual original code-page input')
require(negative['code_signing_hash_counters'] == dict(_cs_validate_page_bad_hash=1, _cs_validate_page_no_hash=0) and
        negative['fatal_user_exit']['cs_status'] == 'CS_KILLED' and negative['fatal_user_exit']['namespace'] == 3 and
        negative['fatal_user_exit']['code'] == 2 and not negative['original_cache_leaf_executed'] and
        not any(e['number'] == 24 for e in negative['syscall_events']), 'Genuine signature checking must refuse before original SVC')
print('PASS: original 16K-signed cache getuid executes its real SVC and returns at native 4K')
print('PASS: same-input, CDHash-qualified code-page mutation is genuinely refused before the original SVC')
print('Full shared cache, launchd main, production root trust and tablet hardware remain unqualified')
