#!/usr/bin/env python3
"""Qualify real PGZ alignment checks and probe-disabled original userspace."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def require(value, message):
    if not value:
        raise SystemExit(message)


def candidate(stem, native, expected):
    path = ROOT / 'build/xnu-prelink' / stem
    plan = json.loads(path.with_suffix('.json').read_text())
    legacy = json.loads((path.parent / 'native-owner-pgz-legacy-probe-candidate.json').read_text())
    require(plan['native_sha256'] == native and plan['candidate_sha256'] == expected ==
            hashlib.sha256(path.with_suffix('.macho').read_bytes()).hexdigest(), 'Exact source/candidate identities')
    require(plan['original_sha256'] == legacy['original_sha256'] and
            plan['original_executable_sha256'] == legacy['original_executable_sha256'] and
            plan['components'] == legacy['components'] and not plan['source_inputs_modified'],
            'Same unchanged original component closure, including AMFI, APFS and corecrypto')
    return expected


def report(label, expected):
    d = json.loads((ROOT / ('build/darwinboot-owner-hvf-pgz-fixed-' + label) / 'gdb-stop.json').read_text())
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(d['kernel_sha256'] == expected and d['qemu_accelerator'] == 'hvf' and
            not d['bounded_timeout_interrupted'] and d['native_4k_mmu_observed'] and
            r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'] and
            d['kernel_page_globals'] == dict(_PAGE_SHIFT_CONST=12, _page_shift=12, _page_shift_user32=12, _page_size=4096),
            'Bounded real HVF observation with active native-4K hardware and runtime globals')
    require(not d['sheng_hardware_tested'] and not d['functional_ipados_boot_demonstrated'], 'Offline scope only')
    return d


probe = candidate('native-owner-pgz-fixed-probe-candidate',
    '85a6eb541ca5771042dcbf3d167f20e8f0c7eddab00a7e6486b7cd851b0e83a7',
    'fd558d17129ae7c6ab53711f2e7d437985a34c43debfd4f51418124e6e35515b')
for mode, label, stage, reason in (
        (1, 'positive', 4, None),
        (2, 'misaligned', 2, "isn't aligned to zone element size"),
        (3, 'wrong-zone', 2, 'not in the expected zone'),
        (4, 'freed', 3, 'probabilistic gzalloc use-after-free')):
    d = report(label, probe)
    a = d['actual_zone_pgz_probe']
    require(a['case'] == mode and a['stage'] == stage and a['metadata'] >> 12 == 10 and
            a['metadata'] & 1023 == a['zone'] and a['backing'] != a['alias'] and
            a['backing'] & 4095 == a['alias'] & 4095 and (a['alias'] & 4095) + 192 <= 4096 and
            a['argument'] == a['alias'] + (mode == 2) and
            (a['expected_zone'] != a['zone']) == (mode == 3), 'Actual controlled PGZ allocation and argument')
    require(d['stop_symbol'] == ('_panic' if reason else '_native_zone_pgz_probe_checkpoint') and
            (reason is None or reason in d['argument_memory']['x0']), 'Positive completion or exact genuine refusal')
print('PASS: real PGZ secondary-page allocation validates, writes through and reclaims; misaligned/wrong-zone/freed controls refuse')

normal = candidate('native-owner-pgz-fixed-candidate',
    'ba60f353a90b61fb6d63425648aeb4475a2c237ed19800d60d2f583cea035bb3',
    'a4a5fd00dbfb3d41ffe7913cc31b14a2db58e27f5d89129d64018e534b9dc309')
symbols = subprocess.check_output(['xcrun', 'nm', '-U', ROOT / 'build/xnu-prelink/native-owner-pgz-fixed-candidate.macho'], text=True)
require('_native_zone_pgz_probe_' not in symbols, 'Allocator instrument absent from normal candidate')
main = report('launchd-main', normal)
require(main['stop_symbol'] == 'original-launchd-main' and main['original_launchd_main_executed'] and
        main['followed_main_entry']['first_instruction_completed'] and int(main['pstate'], 16) & 31 == 0 and
        main['direct_user_commpage_shifts'] == {'fffff4025:1': 12, 'fffff4037:1': 12},
        'Unchanged original launchd executes at EL0 with actual native-4K userspace commpages')
require(main['owner_root_binding_audit']['boot_root_accepted'] and
        main['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80 and
        main['owner_boot_manifest']['status'] == 0 and main['actual_root_composition']['_native_owner_cache_native_union'] == 1 and
        main['original_amfi_table_owner_observed'] and main['original_crypto_initialized_observed'] and
        main['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
        main['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0,
        'Real independent owner roots, original AMFI/crypto and intact storage/code integrity')
print('PASS: probe-disabled original launchd executes with owner roots, original AMFI and native-4K hardware/userspace ABI')

later = report('first-exception', normal)
s = json.loads((ROOT / 'build/native-user-exception/pgz-fixed-symbolication.json').read_text())
require(later['stop_symbol'] == '_exception_triage' and s['kernel_sha256'] == normal and
        int(later['observed_function_entry_arguments'][0], 16) == 6 and
        int(later['observed_function_entry_arguments'][2], 16) == 2 and
        len(later['entry_user_state_candidates']) == 1, 'Actual subsequent two-code user exception, not a kernel panic')
u = later['entry_user_state_candidates'][0]
require(struct.unpack('<2Q', bytes.fromhex(later['entry_regions']['1:0:10']['bytes'])) == (1, int(u['user_pc'], 16)) and
        int(u['cpsr'], 16) & 31 == 0 and int(u['esr'], 16) >> 26 == 0x3c and
        u['instruction_bytes'].startswith('000020d4200020d4') and s['local_symbols_uuid_matches'] and
        s['unique_instruction_match'] == dict(file='dyld_shared_cache_arm64.09', offset=103477996, unslid_pc=6966604524) and
        int(s['cache_slide'], 16) + 6966604524 == int(u['user_pc'], 16) and
        s['frames'][0]['nearest_local_symbol'] == '-[FBSDisplayMonitor _initWithBookendObserver:transformer:]' and
        s['static_original_assertion'] == dict(literal_va='0x1e7a9bf68', text='failed to find the main CADisplay', runtime_string_captured=False),
        'Cross-qualified unchanged FrontBoard EL0 BRK and original assertion reference')
require(later['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
        later['native_signature_hash_cache']['_cs_native4k_full_blocks'] == 201083 and
        later['native_signature_hash_cache']['_cs_native4k_ready_blobs'] == 53 and
        later['native_signature_hash_cache']['_cs_native4k_page_checks'] == 15861 and
        later['owner_root_binding_audit']['boot_root_accepted'] and later['original_amfi_table_owner_observed'] and
        later['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0,
        'Actual continued original startup preserves code/storage integrity and authenticated root')
print('PASS: later original FrontBoard display assertion, 15861 native-4K page validations, zero bad/missing hashes; UI remains open')
