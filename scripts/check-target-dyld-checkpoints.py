#!/usr/bin/env python3
"""Verify genuine original dyld execution and its native-4K page ABI in QEMU."""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
build = ROOT / 'build'
fixture = build / 'target-dyld-fixture'
inputs = json.loads((fixture / 'inputs.json').read_text())
candidate = json.loads((build / 'xnu-prelink/native-target-dyld-candidate.json').read_text())


def require(value, message):
    if not value:
        raise SystemExit('FAIL: ' + message)


for item in inputs['files']:
    data = (fixture / Path(item['path']).name).read_bytes()
    require(hashlib.sha256(data).hexdigest() == item['sha256'], 'unchanged supplied ' + item['path'])
    require(struct.unpack_from('<3I', data) == (0xfeedfacf, 0x100000c, 0), 'ordinary ARM64 target')
root = (fixture / 'root.img').read_bytes()
header = struct.unpack_from('<8sII4Q', root)
require(root[header[3]:header[3] + header[4]] == (fixture / 'launchd').read_bytes() and
        root[header[5]:header[5] + header[6]] == (fixture / 'dyld').read_bytes(), 'byte-exact original files in RAM root')
require(hashlib.sha256(root).hexdigest() == inputs['root_sha256'], 'root identity')
trust = (fixture / 'original-static-trust.bundle').read_bytes()
require(trust[:8] == struct.pack('<2I', 1, 8) and hashlib.sha256(trust[8:]).hexdigest() ==
        inputs['original_static_module_sha256'] == 'da88460e6e513438d5307e5c526f76497a74754476a24da29f239f0c90120fc2',
        'unchanged original static module in loader offset-table container')
require(hashlib.sha256(trust).hexdigest() == inputs['trust_bundle_sha256'], 'trust input identity')
dyld = (fixture / 'dyld').read_bytes()
counts = []
for name in ('darwinboot-target-dyld-cross-page', 'darwinboot-target-dyld-mach-init'):
    d = json.loads((build / name / 'gdb-stop.json').read_text())
    require(d['kernel_sha256'] == candidate['candidate_sha256'] and not d['bounded_timeout_interrupted'],
            'same bounded native kernel/component candidate')
    require(d['target_inputs']['root_sha256'] == inputs['root_sha256'] and
            d['target_inputs']['trust_bundle_sha256'] == inputs['trust_bundle_sha256'], 'exact original boot inputs')
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'], 'actual native hardware 4K MMU')
    g = d['kernel_observations']
    require((g['_PAGE_SHIFT_CONST'], g['_page_shift'], g['_page_size']) == (12, 12, 4096), 'kernel page ABI')
    require(g['_cs_validate_page_bad_hash'] == g['_cs_validate_page_no_hash'] == 0, 'genuine code-page validation')
    require(any(e['module'] == 'com.apple.driver.AppleMobileFileIntegrity' and e['segment'] == '__DATA_CONST'
                and e['va'] <= g['_amfi'] < e['va'] + e['size'] for e in candidate['extents']), 'original AMFI interface owner')
    require(len(d['indirect_memory']) == 2 and all(v['bytes'] == '0c' for v in d['indirect_memory'].values()),
            'actual legacy and read-only commpage user shifts')
    e = d['followed_user_entry']
    require(e['observed'] and int(e['pstate'], 16) & 15 == 0, 'actual original dyld entry at EL0')
    preferred = inputs['dyld_preferred_entry']
    require(e['entry_bytes'] == dyld[preferred:preferred + 16].hex(), 'unchanged original entry instructions')
    slide = int(e['user_entry'], 16) - preferred
    require(slide == int(d['original_dyld_slide'], 16), 'observed ASLR slide, not a guessed entry')
    checkpoint = e['checkpoint']
    require(checkpoint['observed'] and int(checkpoint['pstate'], 16) & 15 == 0, 'original user checkpoint reached')
    confirmed = []
    for step in e['steps']:
        at = int(step['pc'], 16) - slide
        if int(step['pstate'], 16) & 15 == 0 and 0 <= at < 0x80000 - 16 and step['bytes'] == dyld[at:at + 16].hex():
            confirmed.append(step['pc'])
    require(len(set(confirmed)) >= 8 and len(confirmed) == d['original_dyld_el0_instruction_observations'],
            'distinct byte-matched original instructions during real execution')
    counts.append(len(confirmed))
    require(not d['target_launchd_main_executed'] and not d['functional_ipados_boot_demonstrated'] and
            not d['sheng_hardware_tested'], 'qualified checkpoint scope')
    if name.endswith('mach-init'):
        require(d['memory']['fffff4025:1'] == d['memory']['fffff4037:1'] == '0c', 'actual original user commpage ABI bytes')
        returned = e['function_return']
        require(returned['observed'] and int(returned['pstate'], 16) & 15 == 0 and int(returned['x0'], 16) == 0,
                'genuine original mach_init returned successfully at EL0')
        require(d['original_dyld_page_abi'] == dict(_vm_page_size=4096, _vm_page_mask=4095,
                _vm_page_shift=12, _vm_kernel_page_shift=12) and d['original_dyld_native_4k_abi_observed'],
                'original target dyld initialized its own native-4K globals')
        for symbol, expected in d['original_dyld_page_abi'].items():
            width = 8 if symbol in ('_vm_page_size', '_vm_page_mask') else 4
            request = f'{inputs["dyld_symbols"][symbol] - preferred}:{width:x}'
            actual = d['followed_relative_memory'][request]
            require(int(actual['address'], 16) == slide + inputs['dyld_symbols'][symbol] and
                    int.from_bytes(bytes.fromhex(actual['bytes']), 'little') == expected, 'actual target global location/value')

negative = json.loads((build / 'darwinboot-target-dyld-tamper-refusal/gdb-stop.json').read_text())
control = negative['negative_input_control']
require(negative['kernel_sha256'] == candidate['candidate_sha256'] and not negative['bounded_timeout_interrupted'],
        'same bounded target code-page refusal candidate')
require(negative['native_4k_mmu_observed'] and
        negative['target_inputs']['trust_bundle_sha256'] == inputs['trust_bundle_sha256'],
        'native hardware and unchanged original trust in refusal control')
require(control['file_offset'] == 0x372b8 and control['before'] ^ control['after'] == 1 and
        not control['signatures_or_trust_modified'] and not control['supplied_original_file_modified'],
        'isolated one-bit target code-page fault')
damaged = bytearray(root)
damaged[header[5] + control['file_offset']] ^= 1
require(hashlib.sha256(damaged).hexdigest() == control['input_copy_sha256'], 'exact negative input identity')
require(negative['kernel_observations']['_cs_validate_page_bad_hash'] == 1 and
        negative['target_process_exit'] == dict(namespace=3, code=2) and
        not negative['followed_user_entry']['function_return']['observed'], 'genuine CODESIGNING/INVALID_PAGE refusal')

result = dict(candidate_sha256=candidate['candidate_sha256'], target=inputs['target'], checkpoints=3,
              byte_matched_el0_instruction_observations=counts, original_dyld_executed=True,
              original_mach_init_returned=True, original_dyld_page_size=4096,
              original_files_and_static_module_unchanged=True, hardware_translation_native_4k=True,
              corrupt_original_code_page_refused=True,
              target_launchd_main_executed=False, functional_ipados_booted=False,
              apple_boot_trust_chain_verified=False, sheng_hardware_tested=False)
(build / 'target-dyld-checkpoints.json').write_text(json.dumps(result, indent=2) + '\n')
print('PASS: unchanged original dyld executes at native-4K EL0; genuine mach_init returns with page_size=4096')
print('Original launchd main, shared-cache loading, functional iPadOS and hardware remain unqualified')
