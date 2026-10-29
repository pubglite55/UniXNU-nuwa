#!/usr/bin/env python3
"""Qualify actual native-XNU GMU planning, refusal controls and input mappings."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import backed_offset, macho


def require(value, message):
    if not value:
        raise SystemExit(message)


source_hash = '0b8324c7542d208285ffbc63043ca799a151320c7ee4e4f5ad404357ce8dc3fa'
candidate_hash = '23b672c22aed3d493fec8cb4e0ac500222e598c73c72fac250cb09dd7b9e162f'
firmware_hash = '1a2a419c39046d3141fc5fed5aa7f971de2db40cc7a1d89693c3e26fad64dd98'
candidate = ROOT / 'build/xnu-prelink/native-owner-adreno-firmware-candidate.macho'
plan = json.loads(candidate.with_suffix('.json').read_text())
image = candidate.read_bytes()
require(plan['native_sha256'] == source_hash and plan['candidate_sha256'] == candidate_hash ==
        hashlib.sha256(image).hexdigest() and plan['original_sha256'] ==
        'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7', 'Exact source/candidate/original provenance')
build = json.loads((ROOT / 'build/adreno-firmware-probe/build-report.json').read_text())
require(build['kit_revision'] == '7ff8178e6aaf2406bccccacd167f9ce9536b0147' and
        build['firmware_sha256'] == firmware_hash and build['firmware_bytes'] == 66844, 'Pinned actual GMU input and generic implementation')
for name, expected in build['object_sha256'].items():
    data = (ROOT / 'build/adreno-firmware-probe' / name).read_bytes()
    parsed = macho(data)
    version = next(at for cmd, at, _ in parsed['commands'] if cmd == 0x32)
    require(hashlib.sha256(data).hexdigest() == expected and parsed['kind'] == 1 and
            struct.unpack_from('<II', data, version + 8) == (2, 0x110000), 'Actual diagnostic objects must remain ordinary ARM64/iOS 17')

for label in ('native', 'default-off'):
    d = json.loads((ROOT / ('build/darwinboot-owner-hvf-adreno-firmware-' + label) / 'gdb-stop.json').read_text())
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(d['kernel_sha256'] == candidate_hash and d['qemu_accelerator'] == 'hvf' and
            not d['bounded_timeout_interrupted'] and not d['sheng_hardware_tested'] and
            d['native_4k_mmu_observed'] and r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'] and
            d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'], 'Bounded genuine kernel execution and native-4K hardware state')
    state = d['native_adreno_firmware']
    require(state['input_bytes'] == 66844 and not state['gpu_execution_qualified'] and not state['firmware_authenticity_qualified'], 'Do not promote a CPU-side planner/hash check into GPU execution or firmware authenticity')
    capture, span = state['input_capture'], state['input_pages']
    va = int(span['address'], 16)
    at = backed_offset(macho(image)['segments'], va, 66844, len(image))
    require(hashlib.sha256(image[at:at + 66844]).hexdigest() == firmware_hash and
            int(capture['pointer'], 16) == va and capture['bytes'] == image[at:at + 32].hex() and
            span['bytes'] == 66844 and [int(p['virtual_address'], 16) for p in span['pages']] ==
            list(range(va & ~4095, (va + 66844 + 4095) & ~4095, 4096)), 'Actual complete firmware extent and every covered hardware-page sample')
    require(len(span['pages']) == 17 and all(p['leaf_bytes'] in (4096, 2097152) and p['ap'] == 2 and p['pxn'] and p['uxn']
            for p in span['pages']), 'Entire firmware input must use native-4K-granule readonly/NX mappings; 2-MiB block leaves are recorded, not relabeled 4K leaves')
    if label == 'native':
        require(d['stop_symbol'] == '_native_adreno_firmware_checkpoint' and state['requested'] and
                state['status'] == 0 and state['records'] == 15 and state['payload_bytes'] == 66604 and
                state['refusal_mask'] == 15 and state['output_preserved'] == 1 and state['sha256'] == firmware_hash,
                'Actual complete hash/planning plus truncation/capacity/missing-range/owned-copy hash refusals')
    else:
        require(not state['requested'] and state['status'] == -1 and state['records'] == state['payload_bytes'] ==
                state['refusal_mask'] == state['output_preserved'] == 0 and state['sha256'] == '00' * 32 and
                d['original_launchd_main_executed'] and d['followed_main_entry']['first_instruction_completed'] and
                int(d['pstate'], 16) & 31 == 0 and d['direct_user_commpage_shifts'] == {'fffff4025:1': 12, 'fffff4037:1': 12} and
                d['owner_root_binding_audit']['boot_root_accepted'] and d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80 and
                d['original_amfi_table_owner_observed'] and d['actual_signature_failures'] ==
                dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
                d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0,
                'Default-off must preserve original launchd, actual owner-root binding, original signatures and native user 4K')
print('PASS: native-XNU actual GMU plan/hash and four real refusal controls; all input mappings readonly/NX with 4K hardware granule')
print('PASS: probe remains default-off through original launchd main; actual Adreno execution/Metal remain unqualified')
