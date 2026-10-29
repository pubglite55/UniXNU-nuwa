#!/usr/bin/env python3
"""Qualify authenticated real block I/O and refusal before byte exposure."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
import native_prelink as np


def require(value, message):
    if not value:
        raise SystemExit(message)


positive = json.loads((ROOT / 'build/darwinboot-verified-block-cache-getuid/gdb-stop.json').read_text())
negative = json.loads((ROOT / 'build/darwinboot-verified-block-data-refusal/gdb-stop.json').read_text())
expected = [('native-verified-block-candidate', '36058ec38b3477e7eda6651dd1308432b13afda79783f720e8bf75059a9485b0'),
            ('native-verified-block-fault-candidate', 'bc583a1b3e006606f16340d7af95ad966e2566cf33538a10098beaf2b8fbb59b')]
source = (ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed').read_bytes()
old = np.macho(source)
require(hashlib.sha256(source).hexdigest() == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7', 'Require original ordinary-ARM64 target')
policy = (ROOT / 'build/verified-root-systemos/manifest.bin').read_bytes()
key = (ROOT / 'build/verified-root-systemos/trusted-key.bin').read_bytes()
for d, (name, identity) in zip((positive, negative), expected):
    plan = json.loads((ROOT / 'build/xnu-prelink' / (name + '.json')).read_text())
    kernel = (ROOT / 'build/xnu-prelink' / (name + '.macho')).read_bytes()
    meta = np.macho(kernel)
    require(d['kernel_sha256'] == plan['candidate_sha256'] == identity == hashlib.sha256(kernel).hexdigest() and
            not d['bounded_timeout_interrupted'], 'Require exact bounded real candidates')
    exports = np.exports(kernel, meta)
    for symbol, wanted in (('_verified_root_manifest', policy), ('_verified_root_key', key)):
        address = next(a for a, names in exports.items() if symbol in names)
        at = np.backed_offset(meta['segments'], address, len(wanted), len(kernel))
        require(kernel[at:at + len(wanted)] == wanted, 'Both candidates must use the identical actual signed policy and anchor')
    for e in plan['extents']:
        if e['segment'] != '__TEXT_EXEC':
            continue
        at = np.backed_offset(meta['segments'], e['va'], e['size'], len(kernel))
        previous = np.backed_offset(old['segments'], e['va'] - plan['slide'], e['size'], len(source))
        require(kernel[at:at + e['size']] == source[previous:previous + e['size']], 'Original executable code must remain unchanged')
    regs = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(regs['TCR_EL1'] >> 14 & 3 == 0 and regs['TCR_EL1'] >> 30 & 3 == 2 and
            regs['SCTLR_EL1'] & 1 and regs['TTBR0_EL1'] and regs['TTBR1_EL1'], 'Require actual native hardware 4K')
    require(d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'] and
            d['virtio_block_input']['read_only'] and d['native_virtio_integrity']['_native_virtio_manifest_ready'] == 1,
            'Real crypto, signed policy and read-only backend must qualify before DMA data use')
    captures = [v for v in d['indirect_memory'].values() if v['bytes'].startswith(('56524f4f54303100', '56524f4f544b4559'))]
    require(len(captures) == 2, 'Capture actual private metadata/key copies')
    for c in captures:
        t = c['translation']
        require(t['leaf_level'] == 3 and t['leaf_bytes'] == 4096 and t['ap'] == 2 and t['pxn'] and t['uxn'],
                'Actual private policy/anchor copies must have read-only NX native-4K PTEs')
require(positive['original_cache_leaf_executed'] and positive['original_cache_leaf_result'] == 0 and
        positive['native_user_4k_abi_observed'] and positive['original_amfi_table_owner_observed'] and
        positive['native_apfs_data_mount']['mount_result'] == 0 and
        positive['native_apfs_data_mount']['stage'] == 2, 'Original APFS and real original cache SVC must still work')
require(positive['native_virtio_globals']['_native_virtio_read_requests'] == 2035 and
        positive['native_virtio_globals']['_native_virtio_read_failures'] == 0 and
        positive['native_virtio_integrity']['_native_virtio_verified_blocks'] == 26520 and
        positive['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0,
        'Every actual consumed transport span must pass data authentication')
require(positive['code_signing_hash_counters'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
        positive['native_signature_hash_cache']['_cs_native4k_full_blocks'] == 6562 and
        positive['native_virtio_first_sector_sha256'] == '42b1178767bb27611cd1836cdd5779c48bfca8a3e719ec06dc4c8ef78d5e6387',
        'Original data/signatures must retain their real successful checks')
require(negative['function_return_stack_matched'] and int(negative['x0'], 16) == 0xe00002c1 and
        negative['native_virtio_integrity']['_native_virtio_integrity_failures'] == 1 and
        negative['native_virtio_integrity']['_native_virtio_verified_blocks'] == 0 and
        negative['native_virtio_globals']['_native_virtio_ready'] == 0 and
        negative['native_virtio_globals']['_native_virtio_read_requests'] == 1 and
        negative['native_virtio_globals']['_native_virtio_read_failures'] == 0,
        'Authentic DMA with a changed private snapshot must return actual I/O refusal before publication')
for mode in ('', '-verified', '-verified-fault'):
    binding = json.loads((ROOT / ('build/virtio-mmio-block' + mode) / 'bindings.json').read_text())
    require(binding['virtual_methods_checked'] == 190 and binding['concrete_overrides'] == 25 and
            binding['unresolved_original_imports'] == 0, 'All actual concrete storage ABIs must remain qualified')
require('-DNATIVE_VERIFIED_BLOCK_INJECT_FAULT=1' in json.loads((ROOT / 'build/virtio-mmio-block-verified-fault/compile-command.json').read_text()) and
        '-DNATIVE_VERIFIED_BLOCK_INJECT_FAULT=1' not in json.loads((ROOT / 'build/virtio-mmio-block-verified/compile-command.json').read_text()),
        'The negative source-only snapshot injection must be explicit and absent from the positive build')
print('PASS: owner-authenticated real DMA -> CPU snapshot -> original APFS -> original cache code at native 4K')
print('PASS: one changed DMA snapshot byte returns genuine kIOReturnNotPrivileged before media publication')
print('Checks count repeated authenticated reads, not unique/full runtime coverage; production root and hardware remain open')
