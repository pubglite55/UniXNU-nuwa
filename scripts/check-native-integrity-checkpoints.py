#!/usr/bin/env python3
"""Verify saved, bounded QEMU observations of native-4K signed-code validation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--build', type=Path, default=ROOT / 'build')
args = parser.parse_args()
build = args.build


def require(condition, message):
    if not condition:
        raise SystemExit('FAIL: ' + message)


candidate = json.loads((build / 'xnu-prelink/native-hash-cache-runtime.json').read_text())
kernel_sha = candidate['candidate_sha256']
fixture = (build / 'native-user-16k-signature/launchd.macho').read_bytes()
trust = json.loads((build / 'native-user-16k-signature/trustcache.json').read_text())
require(hashlib.sha256(fixture).hexdigest() == trust['process_sha256'], 'own input identity')
observed = []


def report(name, mmu=True):
    d = json.loads((build / name / 'gdb-stop.json').read_text())
    require(d['kernel_sha256'] == kernel_sha, name + ': different kernel')
    require(not d['bounded_timeout_interrupted'], name + ': deadline interrupted')
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require((r['TCR_EL1'] >> 14 & 3) == 0 and (r['TCR_EL1'] >> 30 & 3) == 2,
            name + ': active hardware granules')
    require(r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'], name + ': active MMU')
    if mmu:
        require(d['native_4k_mmu_observed'] and not d['ipados_userspace_boot_demonstrated'],
                name + ': observation scope')
        require(d['original_amfi_table_owner_observed'] and d['original_crypto_initialized_observed'],
                name + ': original security providers')
    observed.append(name)
    return d


def user(d):
    require(d['native_user_el0_observed'] and int(d['pstate'], 16) & 15 == 0, 'actual EL0')
    require(d['native_user_4k_abi_observed'], 'actual userspace 4K ABI')
    require(d['native_user_syscalls'] == dict(pid=1, sysctl_result=0, page_size=4096,
            old_length=4, getpid_carry=0, sysctl_carry=0), 'actual syscalls')
    require(set(d['commpage_user64_shifts'].values()) == {12}, 'both commpage shifts')


def cache(d):
    c = d['native_signature_hash_cache']
    require(c['_cs_native4k_hash_cache_version'] == 1, 'integrity cache version')
    return tuple(c[n] for n in ('_cs_native4k_full_blocks', '_cs_native4k_page_checks',
                                '_cs_native4k_ready_blobs'))


positive = report('darwinboot-native-4k-16k-integrity-runtime')
user(positive)
require(positive['native_user_image_sha256'] == trust['process_sha256'], '16K-signed process identity')
require(positive['trust_cache_bundle_sha256'] == trust['bundle_sha256'], 'explicit test trust identity')
require(cache(positive) == (3, 3, 1), 'whole-block authentication before native page checks')
require(positive['code_signing_hash_counters']['_cs_validate_page_bad_hash'] == 0, 'positive hash result')

inspection = report('darwinboot-native-cache-readonly', mmu=False)
require(int(inspection['x0'], 16) == 0, 'real authentication function returned success')
cd = bytes.fromhex(inspection['entry_indirect_memory']['1:80:200']['bytes'])
length = struct.unpack_from('>I', cd, 4)[0]
require(length <= len(cd) and cd[39] == 14, 'unchanged guest CodeDirectory granule')
require(hashlib.sha256(cd[:length]).hexdigest()[:40] == trust['cdhash'], 'unchanged guest CDHash')
limit = struct.unpack_from('>I', cd, 32)[0]
require(limit == 32976 and struct.unpack_from('>I', cd, 28)[0] == 3, 'original signed extent')
expected = b''.join(hashlib.sha256(fixture[o:min(o + 4096, limit)]).digest()
                    for o in range(0, limit, 4096))
actual = inspection['entry_indirect_memory']['1:b8:1000']
digests = bytes.fromhex(actual['bytes'])
require(digests[:len(expected)] == expected and not any(digests[len(expected):]),
        'derived page digests and zeroed allocation padding')
t = actual['translation']
require(t['leaf_level'] == 3 and t['leaf_bytes'] == 4096 and t['ap'] == 2 and t['pxn'] and t['uxn'],
        'actual hardware read-only, non-executable 4K digest mapping')

for quarter in range(4):
    d = report(f'darwinboot-native-16k-bad-quarter-{quarter}')
    mutated = bytearray(fixture)
    mutated[0x380 if quarter == 0 else quarter * 4096] ^= 1
    require(d['native_user_image_sha256'] == hashlib.sha256(mutated).hexdigest(), 'tamper identity')
    require(not d['native_user_el0_observed'] and cache(d) == (0, 0, 0), 'no unverified publication/EL0')
    require(d['code_signing_hash_counters']['_cs_validate_page_bad_hash'] == 1, 'full-block tamper refusal')
    require((d['exec_policy_refusal']['namespace'], d['exec_policy_refusal']['code']) == (9, 8),
            'actual EXEC/SECURITY_POLICY refusal')

regression = report('darwinboot-native-hash-cache-4k-regression')
user(regression)
require(cache(regression) == (0, 0, 0), 'original 4K integrity path retained')

backing = report('darwinboot-native-cache-post-auth-virtual-md0')
user(backing)
mutation = backing['own_input_mutation']
require(mutation['input_sha256_before'] == trust['process_sha256'] and mutation['byte_offset'] == 0x380,
        'identified backing-input mutation')
require(not mutation['registers_or_validation_state_modified'] and mutation['before'] ^ mutation['after'] == 1,
        'backing mutation scope')
require(backing['code_signing_hash_counters']['_cs_validate_page_bad_hash'] == 0,
        'authentic already-cached vnode pages still validate')

fault = report('darwinboot-native-cache-mapped-page-refusal')
mutation = fault['own_mapped_page_mutation']
require(mutation['page_sha256_before'] == hashlib.sha256(fixture[:4096]).hexdigest(), 'actual fault-page identity')
require(mutation['file_page'] == 0 and mutation['byte_in_page'] == 0x380 and
        mutation['before'] ^ mutation['after'] == 1 and not mutation['registers_or_validation_state_modified'],
        'actual mapped-page mutation scope')
require(cache(fault) == (3, 2, 1), 'post-authentication native page check')
require(fault['code_signing_hash_counters']['_cs_validate_page_bad_hash'] == 1 and
        not fault['native_user_el0_observed'], 'actual fault-page rejection before EL0')
require(fault['stop_symbol'] == '_panic_with_options' and
        (fault['fatal_user_exit']['namespace'], fault['fatal_user_exit']['code']) == (2, 12),
        'observed initproc failure; do not relabel it CODESIGNING/INVALID_PAGE')

result = dict(kernel_sha256=kernel_sha, checkpoints=observed, checkpoint_count=len(observed),
              source='XNU 10063.141.1 with explicit native integrity-cache opt-in',
              own_16k_signed_process_el0=True, native_4k_hardware_observed=True,
              original_codedirectory_unchanged=True, digest_mapping_readonly_nx=True,
              all_four_pre_authentication_quarters_refused=True, mapped_page_tamper_refused=True,
              target_ipados_userspace_executed=False, hardware_tested=False)
(build / 'native-integrity-checkpoints.json').write_text(json.dumps(result, indent=2) + '\n')
print(f'PASS: {len(observed)} saved QEMU checkpoints; original 16K signing blocks, native 4K hardware/EL0')
print('Own static fixture only; target iPadOS execution and sheng hardware remain unverified')
