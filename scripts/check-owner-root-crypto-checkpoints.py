#!/usr/bin/env python3
"""Check real host complete-data verification and native original crypto."""
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


host = json.loads((ROOT / 'build/verified-root-systemos/verification.json').read_text())
inputs = json.loads((ROOT / 'build/verified-root-xnu/inputs.json').read_text())
d = json.loads((ROOT / 'build/darwinboot-owner-crypto-native/gdb-stop.json').read_text())
plan = json.loads((ROOT / 'build/xnu-prelink/native-owner-crypto-candidate.json').read_text())
require(host['real_c_signature_and_block_verification'] and host['blocks_verified'] == 806400 and
        host['image_sha256'] == 'b4908cde41d23e6bc05e6af51a2c9eeb00cf0f863a6a18b1600c96a3fd70414f',
        'Host evidence must cover every original data block')
require(inputs['original_image_sha256'] == host['image_sha256'] and
        inputs['trusted_key_sha256'] == host['trusted_key_sha256'], 'Native probe must use the actual host-qualified input/anchor')
require(d['kernel_sha256'] == plan['candidate_sha256'] ==
        '5da12edb422be5c8043fd524fcabdda0b3a878179cc65ca16efcde04aab5a54e' and
        plan['native_sha256'] == '6cf58f6c0a60dbfa8b20419e8549513a8bb493d357641aed2f9af160a7cd62bf' and
        len(plan['components']) == 14 and not d['bounded_timeout_interrupted'] and d['function_return_stack_matched'],
        'Require the exact same-stack bounded original-component native probe')
regs = {k: int(v, 16) for k, v in d['system_registers'].items()}
require(regs['TCR_EL1'] >> 14 & 3 == 0 and regs['TCR_EL1'] >> 30 & 3 == 2 and
        regs['SCTLR_EL1'] & 1 and regs['TTBR0_EL1'] and regs['TTBR1_EL1'], 'Active hardware translation must be native 4K')
p = d['owner_root_crypto_probe']
require(p['_native_verified_root_status'] == 1 and p['results'] == [0, 4, 3, 3, 4, 5, 2, 1] and
        p['_native_verified_root_signature_calls'] == 4 and p['_native_verified_root_block_count'] == 806400 and
        not p['boot_root_authenticated'], 'Real RSA/header/table/data/key/generation outcomes differ')
require(d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'] and
        any(e['module'] == 'com.apple.driver.AppleMobileFileIntegrity' and e['segment'] == '__DATA_CONST' and
            e['va'] <= p['_amfi'] < e['va'] + e['size'] for e in plan['extents']),
        'Original registered crypto and AMFI must remain active')
for name in ('0:0:40', '1:0:20'):
    t = d['entry_indirect_memory'][name]['translation']
    require(t['leaf_level'] == 3 and t['leaf_bytes'] == 4096 and t['ap'] == 2 and t['pxn'] and t['uxn'],
            'Actual captured metadata/key PTEs must be read-only, NX and native 4K')
require(d['entry_indirect_memory']['0:0:40']['bytes'].startswith('56524f4f54303100') and
        d['entry_indirect_memory']['1:0:20']['bytes'].startswith('56524f4f544b4559'), 'Observe the actual original input/anchor prefixes')
kernel = (ROOT / 'build/xnu-prelink/native-owner-crypto-candidate.macho').read_bytes()
original = (ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed').read_bytes()
meta, old = np.macho(kernel), np.macho(original)
require(hashlib.sha256(kernel).hexdigest() == plan['candidate_sha256'] and hashlib.sha256(original).hexdigest() == plan['original_sha256'],
        'Native/original image identities differ')
for e in plan['extents']:
    if e['segment'] != '__TEXT_EXEC':
        continue
    at = np.backed_offset(meta['segments'], e['va'], e['size'], len(kernel))
    previous = np.backed_offset(old['segments'], e['va'] - plan['slide'], e['size'], len(original))
    require(kernel[at:at + e['size']] == original[previous:previous + e['size']], 'Original executable bytes must not change')
print('PASS: complete original host data verification and actual original RSA/SHA crypto at native 4K')
print('PASS: native signature/table/data/key/generation refusals and read-only NX metadata/key PTEs')
print('Only four original data samples are checked in QEMU; runtime block-path/root acceptance and hardware remain open')
