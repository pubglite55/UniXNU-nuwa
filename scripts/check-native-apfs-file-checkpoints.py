#!/usr/bin/env python3
"""Qualify genuine APFS file signatures and native-4K faults, including refusal."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
import native_prelink as np
build = ROOT / 'build'


def require(value, message):
    if not value:
        raise SystemExit('FAIL: ' + message)


kernel = build / 'xnu-prelink/native-apfs-data-candidate.macho'
data = kernel.read_bytes()
plan = json.loads(kernel.with_suffix('.json').read_text())
require(hashlib.sha256(data).hexdigest() == plan['candidate_sha256'] ==
        '8db7506164cb7772c6af3e8bd21b4a9ee3a951c5c611550deae923ed1558628f' and
        plan['native_sha256'] == 'bad8c94bce1fc6d995671b60f68605ac550cce6074ac6562b27e47162e97427d', 'exact native source/candidate identities')
require(plan['original_sha256'] == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7' and
        not plan['source_inputs_modified'] and not plan['images_modified'], 'unchanged supplied ordinary ARM64 input')
image = np.macho(data)
for e in plan['extents']:
    if e['segment'] == '__TEXT_EXEC':
        at = np.backed_offset(image['segments'], e['va'], e['size'], len(data))
        require(hashlib.sha256(data[at:at + e['size']]).hexdigest() == plan['original_executable_sha256'][e['module']], 'original executable extent retained')


def report(name, candidate=plan['candidate_sha256']):
    d = json.loads((build / name / 'gdb-stop.json').read_text())
    require(d['kernel_sha256'] == candidate and not d['bounded_timeout_interrupted'], 'bounded exact-candidate observation')
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'], 'active native 4K hardware roots')
    return d


positive = report('darwinboot-native-apfs-file-plain')
fault = report('darwinboot-native-apfs-file-cdhash-fault')
mode0 = report('darwinboot-native-apfs-file-ro')
directory = report('darwinboot-native-apfs-file-directory')
old_lookup = report('darwinboot-native-apfs-file', '213d08f953fe38d6b2aab67a2de78aafb2d15af76bbd2cc7582358597a161e5a')
require(old_lookup['native_user_image_sha256'] == directory['native_user_image_sha256'] and
        old_lookup['native_apfs_data_mount']['mkdir_result'] == 2 and
        directory['native_apfs_data_mount']['mkdir_result'] == 0, 'same own program qualifies the intermediate CREATE lookup correction')
require(mode0['native_apfs_data_mount']['mkdir_result'] == 0 and
        mode0['native_apfs_data_mount']['mount_result'] == 1 and
        mode0['native_apfs_data_mount']['mount_nzcv'] >> 29 & 1 and
        mode0['native_apfs_data_mount']['stage'] == 1, 'original user-root mount mode is genuinely refused')
fixture = build / 'native-apfs-file-final-fixture'
metadata = json.loads((fixture / 'file-probe.json').read_text())
own = (fixture / 'launchd.macho').read_bytes()
trust = (fixture / 'offline-file-trust.bundle').read_bytes()
require(metadata['apfs_mount_mode'] == 1 and metadata['apfs_data_mount'] and
        metadata['actual_volume_device'] == '/dev/disk1s1' and not (fixture / 'root.img').exists(), 'actual data-mount mode with a one-file RAM instrument')
require(positive['native_user_image_sha256'] == fault['native_user_image_sha256'] == hashlib.sha256(own).hexdigest() and
        positive['trust_cache_bundle_sha256'] == fault['trust_cache_bundle_sha256'] == hashlib.sha256(trust).hexdigest(), 'identical signed own process and explicit offline file trust')
config = (build / 'darwinboot-native-apfs-file-plain/esp/EFI/UniXNU/unixnu.toml').read_text()
require('rd=md0 ' in config and 'initrd = "Payloads/launchd.macho"' in config, 'explicit own one-file RAM root')
require(positive['native_user_4k_abi_observed'] and positive['native_user_el0_observed'] and
        all(v == 12 for v in positive['commpage_user64_shifts'].values()), 'actual own EL0 syscall and commpage 4K ABI')
m = positive['native_apfs_data_mount']
require(m['mkdir_result'] == m['mount_result'] == m['mkdir_nzcv'] == m['mount_nzcv'] == 0 and m['stage'] == 2, 'real devfs directory and read-only APFS data mount succeed')
f = positive['native_file_probe']
require(f['open_result'] >= 0 and f['fcntl_result'] == 0 and f['mmap_result'] % 4096 == 0 and f['mmap_result'] > 0 and
        f['open_nzcv'] == f['fcntl_nzcv'] == f['mmap_nzcv'] == 0 and
        f['signature_end'] == metadata['code_limit'] == 32768 and f['stage'] == 4 and
        f['native_pages_read'] == metadata['expected_native_pages'] == 8 and
        f['page_word_xor'] == metadata['expected_page_word_xor'], 'actual APFS open, F_ADDFILESIGS_RETURN, RX mmap and eight 4K accesses')
for d in (positive, fault):
    require(d['original_crypto_initialized_observed'] and d['original_amfi_table_owner_observed'], 'genuine original crypto and AMFI remain active')
    g = d['native_virtio_globals']
    require(g['_native_virtio_read_requests'] == 138 and g['_native_virtio_read_failures'] == 0 and
            g['_native_virtio_sectors'] * 512 == 3303014400, 'actual original data-volume I/O')
    h = d['native_signature_hash_cache']
    require(h['_cs_native4k_full_blocks'] == 5 and h['_cs_native4k_ready_blobs'] == 2, 'real original-block authentication before native-4K faults')
require(positive['code_signing_hash_counters']['_cs_validate_page_bad_hash'] == 0 and
        positive['code_signing_hash_counters']['_cs_validate_page_no_hash'] == 0, 'positive signature policy remains satisfied')
source = ROOT / '.cache/firmware/target-volumes/systemos-mount/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.02'
cache = source.read_bytes()
require(hashlib.sha256(cache).hexdigest() == metadata['original_file_sha256'] ==
        '3d923c404fe519184a99042b60a4cb3d37247dcb8b070242ed3e670d4d523d04', 'supplied original cache file remains unchanged')
sigoff, sigsize = struct.unpack_from('<QQ', cache, 40)
signature = cache[sigoff:sigoff + sigsize]
directories = []
for index in range(struct.unpack_from('>I', signature, 8)[0]):
    _, at = struct.unpack_from('>II', signature, 12 + index * 8)
    magic, size = struct.unpack_from('>II', signature, at)
    if magic == 0xfade0c02:
        directories.append(signature[at:at + size])
require(len(directories) == 1 and directories[0][39] == 14, 'actual original 16K CodeDirectory remains intact')
cd = directories[0]
hashoff = struct.unpack_from('>I', cd, 16)[0]
require(hashlib.sha256(cd).digest()[:20].hex() == metadata['original_cdhash'] and
        all(hashlib.sha256(cache[i:i + 16384]).digest() == cd[hashoff + i // 16384 * 32:hashoff + (i // 16384 + 1) * 32]
            for i in range(0, 32768, 16384)), 'original signing blocks and actual CodeDirectory identity')
event = fault['own_mapped_page_mutation']
require(event['file_page'] == 4096 and event['byte_in_page'] == 7 and
        event['before'] == cache[4103] and event['after'] == cache[4103] ^ 1 and
        event['page_sha256_before'] == hashlib.sha256(cache[4096:8192]).hexdigest() and
        event['code_directory_hash'] == metadata['original_cdhash'] == '9d037a68ad6490e103e44e47086e279a2923b04e' and
        event['compiled_cdhash_field_offset'] == 0x58 and not event['registers_or_validation_state_modified'], 'actual signed original-cache identity and one-byte VM input fault')
require(fault['code_signing_hash_counters']['_cs_validate_page_bad_hash'] == 1 and
        fault['code_signing_hash_counters']['_cs_validate_page_no_hash'] == 0 and
        fault['fatal_user_exit']['cs_status'] == 'CS_KILLED' and
        fault['fatal_user_exit']['namespace'] == 3 and fault['fatal_user_exit']['code'] == 2, 'genuine CODESIGNING bad-page refusal')
mount_results = struct.unpack('<5Q', bytes.fromhex(fault['native_user_memory']['_apfs_mount_results']))
file_results = struct.unpack('<10Q', bytes.fromhex(fault['native_user_memory']['_file_probe_results']))
require(mount_results == (0, 0, 0, 0, 2) and file_results[9] == 3 and
        file_results[8] == 32768, 'fault occurs after genuine data mount, signature registration and mmap')
result = dict(candidate_sha256=plan['candidate_sha256'], native_sha256=plan['native_sha256'],
              checked_qemu_reports=5, original_executable_code_modified=False, target_cache_modified=False,
              real_apfs_data_mount=True, native_4k=True, original_signing_block_bytes=16384,
              actual_rx_fault_pages=8, dma_reads=138, dma_failures=0,
              cache_page_fault_cdhash=event['code_directory_hash'], actual_bad_hash_refused=True,
              original_user_root_mount_mode_refused=True, explicit_offline_ram_root=True,
              production_root_authenticated=False, original_dyld_cache_loader_qualified=False,
              functional_ipados_booted=False, hardware_tested=False)
(build / 'native-apfs-file-checkpoints.json').write_text(json.dumps(result, indent=2) + '\n')
print('PASS: genuine APFS data mount, original 16K-signed cache file and 8 native-4K RX faults; identity-qualified bad page is refused')
print('Explicit own RAM root/file trust is an offline instrument; production root, complete dyld cache, UI and hardware remain unqualified')
