#!/usr/bin/env python3
"""Qualify the real native parameter helper, guards, refusals and default-off path."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import macho, exports, backed_offset


def require(value, message):
    if not value:
        raise SystemExit(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


source_hash = 'f162b0a2c4fc0f45760a0fcaaf940d3039d6bb26310b79a2810ed16bf5c7e571'
candidate_hash = 'ac7c4b2ef5f427392b7a314939112e66151f815594ee5651eff8076a2d8bb0a1'
candidate = ROOT / 'build/xnu-prelink/native-owner-constants-outer-candidate.macho'
plan = json.loads(candidate.with_suffix('.json').read_text())
image = candidate.read_bytes()
require(plan['native_sha256'] == source_hash and plan['candidate_sha256'] == candidate_hash == sha(image) and
        plan['original_sha256'] == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7' and
        len(plan['components']) == 29 and not plan['images_modified'] and not plan['source_inputs_modified'],
        'Exact native build/candidate and unchanged supplied target components')
build_dir = ROOT / 'build/constant-uploads-probe'
build = json.loads((build_dir / 'build-report.json').read_text())
require(build['kit_revision'] == '2805ae10bf64af7e3517660189b2a0d5073febe6' and
        not build['gpu_execution'] and not build['submission_authorized'], 'Exact parameter implementation and evidence limits')
for name, digest in build['source_sha256'].items():
    require(sha((ROOT / name).read_bytes()) == digest, 'Native fixture/kit source identity')
require(sha((ROOT / 'kits/AirNir/ConstantUploads.h').read_bytes()) == build['header_sha256'], 'Exact C ABI header')
require(sha((build_dir / 'libConstantUploadsProbe.a').read_bytes()) == build['archive_sha256'], 'Current archive identity')
for name, digest in build['object_sha256'].items():
    raw = (build_dir / name).read_bytes()
    parsed = macho(raw)
    version = next(at for cmd, at, _ in parsed['commands'] if cmd == 0x32)
    require(sha(raw) == digest and parsed['kind'] == 1 and struct.unpack_from('<II', raw, version + 8) == (2, 0x110000),
            'Actual ordinary ARM64/iOS-17 kernel objects')
    member = subprocess.check_output(['xcrun', 'ar', '-p', build_dir / 'libConstantUploadsProbe.a', name])
    require(member == raw, 'Exact archive members, independent of archive timestamps')
# The freestanding helper has one relocation-free text section and no runtime
# imports. Compare every compiled instruction to the actual candidate, rather
# than treating a newly recreated archive timestamp/hash as linked provenance.
raw = (build_dir / 'ConstantUploads.o').read_bytes()
parsed = macho(raw)
text = next(s for segment in parsed['segments'] for s in segment['sections'] if s['name'] == '__text')
require(struct.unpack_from('<I', raw, text['command_offset'] + 60)[0] == 0 and
        not subprocess.check_output(['xcrun', 'nm', '-u', build_dir / 'ConstantUploads.o']).strip(),
        'Actual helper has no text relocations or runtime imports')
code = raw[text['fileoff']:text['fileoff'] + text['size']]
parsed_image = macho(image)
addresses = [va for va, names in exports(image, parsed_image).items() if '_air_pack_constants' in names]
require(len(addresses) == 1, 'Unique actual helper in candidate')
offset = backed_offset(parsed_image['segments'], addresses[0], len(code), len(image))
require(image[offset:offset + len(code)] == code, 'Every native helper instruction matches the linked candidate')
reports = {}
for label in ('native', 'enabled-main', 'default-off'):
    d = json.loads((ROOT / ('build/darwinboot-owner-hvf-constants-' + label) / 'gdb-stop.json').read_text())
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(d['kernel_sha256'] == candidate_hash and d['qemu_accelerator'] == 'hvf' and
            not d['bounded_timeout_interrupted'] and not d['sheng_hardware_tested'] and
            d['native_4k_mmu_observed'] and (r['TCR_EL1'] >> 14) & 3 == 0 and (r['TCR_EL1'] >> 30) & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'] and
            d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'],
            'Bounded actual XNU with active native-4K CPU translation')
    state = d['native_constant_uploads']
    require(not state['gpu_execution_qualified'], 'Parameter copies are not GPU execution')
    if label != 'default-off':
        require(state['requested'] and state['status'] == 0 and state['refusal_mask'] == 1023 and
                state['output_preserved'] == 1 and state['written_bytes'] == 144 and state['padded_bytes'] == 104,
                'Real positive and ten transactional native refusals')
    else:
        require(not state['requested'] and state['status'] == -1 and
                all(state[k] == 0 for k in ('refusal_mask', 'output_preserved', 'written_bytes', 'padded_bytes', 'allocations_released')) and
                set(state['physical']) == {'0x0'}, 'Default-off must perform no diagnostic work/allocation')
    if label != 'native':
        require(all(int(state[k], 16) == 0 for k in ('a_pointer', 'b_pointer', 'output_pointer')) and
                state['allocations_released'] == (label == 'enabled-main') and
                d['original_launchd_main_executed'] and d['followed_main_entry']['first_instruction_completed'] and
                int(d['pstate'], 16) & 31 == 0 and
                d['direct_user_commpage_shifts'] == {'fffff4025:1': 12, 'fffff4037:1': 12} and
                d['owner_root_binding_audit']['boot_root_accepted'] and
                d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80 and
                d['original_amfi_table_owner_observed'] and d['actual_signature_failures'] ==
                dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
                d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0,
                'Allocation release before real original EL0 launchd; user-4K and signature/root checks remain intact')
    reports[label] = d
native = reports['native']
state = native['native_constant_uploads']
require(native['stop_symbol'] == '_native_constants_checkpoint' and not state['allocations_released'], 'Live allocated checkpoint')
r = {k: int(v, 16) for k, v in native['system_registers'].items()}
mask = 0x0000fffffffff000
for i, label in enumerate(('a', 'b', 'output')):
    allocation = state[label]
    span = allocation['cpu_mappings']
    va = int(state[label + '_pointer'], 16)
    physical = [int(v, 16) for v in state['physical'][2*i:2*i+2]]
    require(va and not va & 4095 and physical[0] and physical[1] == 0 and span['address'] == hex(va) and
            span['bytes'] == 8192 and len(span['pages']) == 2, 'Actual page plus adjacent real guard')
    for j, page in enumerate(span['pages']):
        pointer = va + j * 4096
        require(int(page['virtual_address'], 16) == pointer, 'Exact allocation and adjacent guard addresses')
        bits = 64 - ((r['TCR_EL1'] >> 16) & 63)
        start = 4 - ((bits - 12 + 8) // 9)
        table = r['TTBR1_EL1'] & mask
        walk = page['walk']
        require(len(walk) == 4 - start, 'Complete independent actual TTBR1 walk')
        for level, step in zip(range(start, 4), walk):
            descriptor = int(step['descriptor'], 16)
            address = table + ((((pointer & ((1 << bits) - 1)) >> (39 - 9 * level)) & 511) * 8)
            require(step['level'] == level and int(step['descriptor_pa'], 16) == address,
                    'Descriptor follows the active native TTBR and 4K indices')
            if j and level == 3:
                require(not descriptor & 1 and page['mapped'] is False, 'Guard has no valid hardware leaf')
            else:
                require(descriptor & 3 == 3, 'Native table/page descriptor; no block/conversion/shadow tables')
            table = descriptor & mask
        if not j:
            require(table == physical[0] and page['leaf_level'] == 3 and page['leaf_bytes'] == 4096 and
                    int(page['physical_address'], 16) == physical[0] and page['ap'] == 0 and page['pxn'] and page['uxn'] and
                    page['accessed'] and page['shareability'] == 2, 'Actual real 4K RW/NX source/output page')
    capture = allocation['capture']
    require(int(capture['pointer'], 16) == int(capture['address'], 16) == va, 'Actual allocation byte capture')
    raw = bytes.fromhex(capture['bytes'])
    expected = bytearray(b'\x39' * 4096 if label == 'a' else b'\x49' * 4096 if label == 'b' else b'\x6b' * 4096)
    if label == 'a': expected[-8:] = bytes(range(1, 9))
    elif label == 'b': expected[-80:] = bytes(range(17, 97))
    else:
        expected[3840+64:3840+128] = bytes(range(1, 9)) + bytes(56)
        expected[3840+128:3840+192] = bytes(range(81, 97)) + bytes(48)
        expected[3840+208:3840+224] = struct.pack('<4I', 0x11223344, 0x89abcdef, 0, 0xffffffff)
    require(raw == expected, 'Complete sources unchanged and exact parameters/padding with all other bytes untouched')
(build_dir / 'native-checkpoint.json').write_text(json.dumps(dict(
    kit_revision=build['kit_revision'], source_sha256=source_hash, candidate_sha256=candidate_hash,
    helper_instruction_sha256=sha(code), helper_instruction_bytes=len(code),
    refusals=10, written_bytes=144, padded_bytes=104,
    actual_cpu_leaf_bytes=4096, actual_guard_pages=3, allocations_released_before_original_main=True,
    default_off_original_main=True, gpu_execution=False, hardware_observed=False), indent=2) + '\n')
print('PASS: same native helper instructions, actual 4K pages/guards, exact parameter bytes and ten transactional refusals')
print('PASS: enabled allocation release and default-off original launchd/signatures/user-4K; no GPU/Metal claim')
