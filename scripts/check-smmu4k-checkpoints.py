#!/usr/bin/env python3
"""Check native inactive tables against actual XNU allocation and CPU mappings."""
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import macho


def require(value, message):
    if not value:
        raise SystemExit(message)


# Filled from the exact post-shareability build, never from target binaries in Git.
plan = json.loads((ROOT / 'build/xnu-prelink/native-owner-smmu4k-outer-candidate.json').read_text())
source_hash = 'ad9041065a939cdc04235faa1f88bda693a04666cae66625cb5fa1c01ebc0fe7'
candidate_hash = '5a838595de36a70224e2a21b24f42db62b734f7b35376ff7a0b1ee699b51efb0'
image = (ROOT / 'build/xnu-prelink/native-owner-smmu4k-outer-candidate.macho').read_bytes()
require(plan['native_sha256'] == source_hash and plan['candidate_sha256'] == candidate_hash ==
        hashlib.sha256(image).hexdigest() and plan['original_sha256'] ==
        'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7' and
        len(plan['components']) == 29 and not plan['images_modified'] and not plan['source_inputs_modified'],
        'Exact source/candidate and unchanged target provenance')
build = json.loads((ROOT / 'build/smmu4k-probe/build-report.json').read_text())
require(build['kit_revision'] == '32c74a03c8bbbdb82fed1cb6ee59a5824878f81f' and not build['gpu_execution'] and not build['submission_authorized'],
        'Exact inactive-table implementation; no GPU execution claim')
for name, digest in build['object_sha256'].items():
    raw = (ROOT / 'build/smmu4k-probe' / name).read_bytes()
    parsed = macho(raw)
    version = next(at for cmd, at, _ in parsed['commands'] if cmd == 0x32)
    require(hashlib.sha256(raw).hexdigest() == digest and parsed['kind'] == 1 and
            struct.unpack_from('<II', raw, version + 8) == (2, 0x110000), 'Actual ordinary ARM64/iOS-17 diagnostic objects')
reports = {}
for label in ('native', 'enabled-main', 'default-off'):
    d = json.loads((ROOT / ('build/darwinboot-owner-hvf-smmu4k-' + label) / 'gdb-stop.json').read_text())
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(d['kernel_sha256'] == candidate_hash and d['qemu_accelerator'] == 'hvf' and
            not d['bounded_timeout_interrupted'] and not d['sheng_hardware_tested'] and
            d['native_4k_mmu_observed'] and (r['TCR_EL1'] >> 14) & 3 == 0 and (r['TCR_EL1'] >> 30) & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'] and
            d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'],
            'Bounded real XNU execution and active native-4K CPU translation')
    state = d['native_smmu4k']
    require(not state['smmu_activated'] and not state['gpu_execution_qualified'], 'Do not qualify inactive tables as live SMMU/GPU execution')
    if label != 'default-off':
        require(state['requested'] and state['status'] == 0 and state['table_pages'] == 5 and state['leaf_pages'] == 2 and
                state['refusal_mask'] == 63 and state['output_preserved'] == 1, 'Real native table building and six transactional refusal controls')
    else:
        require(not state['requested'] and state['status'] == -1 and
                all(state[k] == 0 for k in ('table_pages', 'leaf_pages', 'refusal_mask', 'output_preserved', 'allocations_released')) and
                int(state['cpu_mair'], 16) == 0 and set(state['pool_physical'] + state['data_physical']) == {'0x0'},
                'Default-off must perform no diagnostic allocation or table work')
    if label != 'native':
        require(int(state['pool_pointer'], 16) == int(state['data_pointer'], 16) == 0 and
                state['allocations_released'] == (label == 'enabled-main') and
                d['original_launchd_main_executed'] and d['followed_main_entry']['first_instruction_completed'] and
                int(d['pstate'], 16) & 31 == 0 and
                d['direct_user_commpage_shifts'] == {'fffff4025:1': 12, 'fffff4037:1': 12} and
                d['owner_root_binding_audit']['boot_root_accepted'] and
                d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80 and
                d['original_amfi_table_owner_observed'] and d['actual_signature_failures'] ==
                dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
                d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0,
                'Native allocations returned before original EL0 launchd; security/root and user-4K remain intact')
    reports[label] = d

native = reports['native']
state = native['native_smmu4k']
require(native['stop_symbol'] == '_native_smmu4k_checkpoint' and not state['allocations_released'], 'Real checkpoint retains actual allocated input/output for inspection')
registers = {k: int(v, 16) for k, v in native['system_registers'].items()}
mask = 0x0000fffffffff000
for label, count in (('pool', 6), ('data', 2)):
    capture = state[label]
    va = int(state[label + '_pointer'], 16)
    physical = [int(v, 16) for v in state[label + '_physical']]
    span = capture['cpu_mappings']
    require(va and not va & 4095 and physical == list(range(physical[0], physical[0] + count * 4096, 4096)) and
            span['address'] == hex(va) and span['bytes'] == count * 4096 and len(span['pages']) == count,
            'Real allocated aligned/contiguous physical extent and complete CPU mapping coverage')
    for i, page in enumerate(span['pages']):
        pointer = va + i * 4096
        require(int(page['virtual_address'], 16) == pointer and int(page['physical_address'], 16) == physical[i] and
                page['leaf_level'] == 3 and page['leaf_bytes'] == 4096 and page['ap'] == 0 and
                page['pxn'] and page['uxn'] and page['accessed'] and page['shareability'] == 2 and
                (int(state['cpu_mair'], 16) >> (8 * page['attr_index'])) & 255 == 255,
                'Every actual allocation page uses a real 4K RW/NX WB/outer-shareable CPU leaf')
        table = registers['TTBR1_EL1'] & mask
        bits = 64 - ((registers['TCR_EL1'] >> 16) & 63)
        start = 4 - ((bits - 12 + 8) // 9)
        walk = page['walk']
        require(len(walk) == 4 - start, 'Complete actual TTBR1 physical walk')
        for level, step in zip(range(start, 4), walk):
            descriptor = int(step['descriptor'], 16)
            address = table + ((((pointer & ((1 << bits) - 1)) >> (39 - 9 * level)) & 511) * 8)
            require(step['level'] == level and int(step['descriptor_pa'], 16) == address and descriptor & 3 == 3,
                    'Recorded physical descriptors must follow the active TTBR and exact native 4K indices')
            table = descriptor & mask
        require(table == physical[i], 'Actual CPU leaf resolves to the independently captured kernel physical address')
    require(len(capture['chunks']) == count, 'Complete allocated memory capture')
    for i, chunk in enumerate(capture['chunks']):
        require(int(chunk['pointer'], 16) == va and int(chunk['address'], 16) == va + i * 4096 and
                len(bytes.fromhex(chunk['bytes'])) == 4096, 'Each actual allocation page is read without changing it')

pool = b''.join(bytes.fromhex(c['bytes']) for c in state['pool']['chunks'])
data = b''.join(bytes.fromhex(c['bytes']) for c in state['data']['chunks'])
require(data == b'\x39' * 8192 and pool[5 * 4096:] == b'\xa5' * 4096, 'Actual resource bytes and unused table-pool page remain intact')
root = int(state['pool_physical'][0], 16)
expected = {0x1ff000: int(state['data_physical'][0], 16), 0x200000: int(state['data_physical'][1], 16)}
seen, leaves = set(), {}


def visit(index, level, prefix):
    require(0 <= index < 5 and index not in seen, 'Owned noncyclic inactive table graph')
    seen.add(index)
    for slot in range(512):
        descriptor, = struct.unpack_from('<Q', pool, index * 4096 + slot * 8)
        if not descriptor:
            continue
        va = prefix | (slot << (39 - level * 9))
        if level < 3:
            require(descriptor & ~mask == 3 and root <= descriptor & mask < root + 5 * 4096,
                    'Only owned native table descriptors; no block, foreign table or page-size conversion')
            visit(((descriptor & mask) - root) // 4096, level + 1, va)
        else:
            require(descriptor & ~mask == (3 << 53) | 0xe47, 'Exact inactive 4K RW/NX WB/outer-shareable leaf attributes')
            leaves[va] = descriptor & mask


visit(0, 0, 0)
require(len(seen) == 5 and leaves == expected, 'Complete inactive graph maps exactly the two actual resource pages across the 2-MiB boundary')
(ROOT / 'build/arm-smmu-4k/native-checkpoint.json').write_text(json.dumps(dict(
    source_sha256=source_hash, candidate_sha256=candidate_hash, table_pages=5, leaf_pages=2,
    real_contiguous_allocations=True, cpu_leaf_bytes=4096, cpu_wb_outer_observed=True,
    inactive_leaf_bytes=4096, inactive_wb_outer_observed=True,
    smmu_activated=False, gpu_coherency_qualified=False, metal_qualified=False), indent=2) + '\n')
print('PASS: actual XNU physical allocation, native 4K CPU mappings, complete inactive 4K table graph and six real refusals')
print('PASS: allocation release and original launchd/security with enabled/default-off fixture; no active SMMU/GPU/Metal claim')
