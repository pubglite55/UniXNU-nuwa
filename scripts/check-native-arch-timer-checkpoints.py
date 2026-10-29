#!/usr/bin/env python3
"""Require real architectural timer boot without the BCM-specific early write."""
import hashlib
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]
base = runpy.run_path(str(ROOT / 'scripts/check-original-launchd-main-checkpoints.py'))
require = base['require']
expected = base['candidate']('native-owner-arch-timer-candidate',
    '8bd4387f7a1b83ceb76ed9d8d7ab4c32c497a48de00eb32e8d080d6c80582a90',
    '655825844686147147aba8e76ca02c2871a1b95df170e332e92a49e2df604d47')
directory = ROOT / 'build/native-arch-timer'
r = json.loads((directory / 'qualification.json').read_text())
sequence = bytes.fromhex('af0038d5ef1d4092000088d200bc70d30000019100080f8b011e8052010000b9df3f03d5')
for mode, stem, count in (('legacy', 'legacy-start', 1), ('architectural', 'architectural-start', 0)):
    obj = (directory / (stem + '.o')).read_bytes()
    args = json.loads((directory / (stem + '.o.json')).read_text().rstrip(',\n'))['arguments']
    require(hashlib.sha256(obj).hexdigest() == r[mode + '_object_sha256'] and obj.count(sequence) == count and
            'XNU_NATIVE_ARCH_TIMER=' + str(1 - count) in args,
            'Actual assembly command/object must retain legacy or remove the complete specific MMIO sequence')
image = (ROOT / 'build/xnu-prelink/native-owner-arch-timer-candidate.macho').read_bytes()
require(image.count(sequence) == 0 and r['linked_sequence_count'] == 0, 'Linked candidate contains no legacy routing sequence')
d = base['report']('owner-hvf-arch-timer-launchd-main')
require(d['kernel_sha256'] == expected and d['native_4k_mmu_observed'] and not d['bounded_timeout_interrupted'] and
        d['stop_symbol'] == 'original-launchd-main' and d['original_launchd_main_executed'] and
        d['followed_main_entry']['first_instruction_completed'] and int(d['pstate'], 16) & 31 == 0 and
        d['direct_user_commpage_shifts'] == {'fffff4025:1': 12, 'fffff4037:1': 12},
        'Actual original launchd must still execute at native-4K EL0')
a = d['armcpu_globals']
require(a['_armcpu_registered'] == a['_armcpu_gic_ready'] == a['_gCPUsRunning'] == 1 and
        a['_armcpu_timer_interrupts'] == 243286 and a['_armcpu_ipi_interrupts'] == 0,
        'Real architectural GIC/timer must interrupt; no observed IPI or SMP claim')
require('owner_cache_carrier' not in d and d['actual_root_composition']['_native_owner_cache_native_union'] == 1 and
        d['owner_root_binding_audit']['boot_root_accepted'] and d['owner_boot_manifest']['status'] == 0 and
        d['original_amfi_table_owner_observed'] and d['actual_signature_failures'] ==
        dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
        not d['functional_ipados_boot_demonstrated'] and not d['sheng_hardware_tested'],
        'Preserve owner authentication, original policy and honest offline scope')
print('PASS: legacy BCM pre-MMU write absent from actual architectural entry object and linked candidate')
print('PASS: 243286 actual timer interrupts, original launchd LC_MAIN at EL0, native hardware 4K and user shifts 12/12')
