#!/usr/bin/env python3
"""Qualify real native-XNU PM4 CPU-side behavior and the default-off control."""
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


source_hash = '61c1a8ef1bd924dae5a879987f85a294322d9821e1c073d498e24f6e9dee0b61'
candidate_hash = 'b43d5a6d41ff35140692472bb9671d77078518cdc631c1a642121cce7a5bb310'
candidate = ROOT / 'build/xnu-prelink/native-owner-adreno-pm4-candidate.macho'
plan = json.loads(candidate.with_suffix('.json').read_text())
require(plan['native_sha256'] == source_hash and plan['candidate_sha256'] == candidate_hash ==
        hashlib.sha256(candidate.read_bytes()).hexdigest() and plan['original_sha256'] ==
        'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7' and
        not plan['images_modified'] and not plan['source_inputs_modified'] and len(plan['components']) == 28,
        'Exact source, unchanged target input and original-component candidate provenance')
build = json.loads((ROOT / 'build/adreno-pm4-probe/build-report.json').read_text())
require(build['kit_revision'] == '34c9dd054d78cb7b357257fba73848abf7b6698e' and
        not build['gpu_execution'] and not build['submission_authorized'], 'Exact PM4 kit; no GPU execution or submission claim')
for name, expected in build['object_sha256'].items():
    data = (ROOT / 'build/adreno-pm4-probe' / name).read_bytes()
    image = macho(data)
    version = next(at for cmd, at, _ in image['commands'] if cmd == 0x32)
    require(hashlib.sha256(data).hexdigest() == expected and image['kind'] == 1 and
            struct.unpack_from('<II', data, version + 8) == (2, 0x110000), 'Actual native diagnostic objects are ordinary ARM64/iOS 17')
for label in ('native', 'default-off'):
    d = json.loads((ROOT / ('build/darwinboot-owner-hvf-adreno-pm4-' + label) / 'gdb-stop.json').read_text())
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(d['kernel_sha256'] == candidate_hash and d['qemu_accelerator'] == 'hvf' and
            not d['bounded_timeout_interrupted'] and not d['sheng_hardware_tested'] and
            d['native_4k_mmu_observed'] and r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'] and
            d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'],
            'Bounded actual kernel execution with active native-4K hardware translation')
    state = d['native_adreno_pm4']
    require(not state['gpu_execution_qualified'] and not state['submission_authorized'], 'Do not promote structural planning into real GPU submission')
    if label == 'native':
        require(d['stop_symbol'] == '_native_adreno_pm4_checkpoint' and state['requested'] and state['status'] == 0 and
                state['packets'] == 3 and state['refusal_mask'] == 63 and state['bit_refusals'] == 64 and
                state['input_preserved'] == state['output_preserved'] == 1,
                'Actual packet plans, six refusal classes, 64 bit corruptions and unchanged buffers')
    else:
        require(not state['requested'] and state['status'] == -1 and
                all(state[name] == 0 for name in ('packets', 'refusal_mask', 'output_preserved', 'bit_refusals', 'input_preserved')) and
                d['original_launchd_main_executed'] and d['followed_main_entry']['first_instruction_completed'] and
                int(d['pstate'], 16) & 31 == 0 and d['direct_user_commpage_shifts'] == {'fffff4025:1': 12, 'fffff4037:1': 12} and
                d['owner_root_binding_audit']['boot_root_accepted'] and d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80 and
                d['original_amfi_table_owner_observed'] and d['actual_signature_failures'] ==
                dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
                d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0,
                'Default-off preserves original EL0 launchd, native user 4K, real owner binding and original signing enforcement')
print('PASS: native-XNU PM4 mixed plans, six refusal classes, 64 header corruptions and unchanged input/output')
print('PASS: default-off original launchd, native user 4K and signatures; GPU execution and Metal remain unqualified')
