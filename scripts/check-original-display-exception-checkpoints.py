#!/usr/bin/env python3
"""Require actual original FrontBoard EL0 exception and matching cache symbolication."""
import json
from pathlib import Path
import runpy
import struct

ROOT = Path(__file__).resolve().parents[1]
base = runpy.run_path(str(ROOT / 'scripts/check-native-arch-timer-checkpoints.py'))
require = base['require']
d = json.loads((ROOT / 'build/darwinboot-owner-hvf-arch-timer-first-exception/gdb-stop.json').read_text())
s = json.loads((ROOT / 'build/native-user-exception/arch-timer-qualified-symbolication.json').read_text())
require(d['kernel_sha256'] == s['kernel_sha256'] == base['expected'] and
        d['stop_symbol'] == '_exception_triage' and not d['bounded_timeout_interrupted'] and
        int(d['observed_function_entry_arguments'][0], 16) == 6 and
        int(d['observed_function_entry_arguments'][2], 16) == 2 and len(d['entry_user_state_candidates']) == 1,
        'Real two-code EXC_BREAKPOINT entry on the exact architectural timer candidate')
u = d['entry_user_state_candidates'][0]
require(struct.unpack('<2Q', bytes.fromhex(d['entry_regions']['1:0:10']['bytes'])) == (1, int(u['user_pc'], 16)) and
        int(u['cpsr'], 16) & 31 == 0 and int(u['esr'], 16) >> 26 == 0x3c and
        u['instruction_bytes'].startswith('000020d4200020d4') and u['user_pc'] == u['user_lr'],
        'Actual saved ABI, EL0, exception code, ESR and original BRK must agree')
require(s['unique_instruction_match'] == dict(file='dyld_shared_cache_arm64.09', offset=103477996, unslid_pc=6966604524) and
        int(s['cache_slide'], 16) + 6966604524 == int(u['user_pc'], 16) and s['local_symbols_uuid_matches'] and
        s['frames'][0]['nearest_local_symbol'] == '-[FBSDisplayMonitor _initWithBookendObserver:transformer:]' and
        s['frames'][0]['offset'] == 1148 and
        s['frames'][1]['nearest_local_symbol'] == '___34+[FBDisplayManager sharedInstance]_block_invoke' and
        any(f['image'] == '/System/Library/PrivateFrameworks/SpringBoard.framework/SpringBoard' for f in s['frames']) and
        s['frames'][-1]['image'] == '/usr/lib/dyld', 'Original uniquely matched code and UUID-bound symbols qualify the actual call chain')
require(s['static_original_assertion'] == dict(literal_va='0x1e7a9bf68', text='failed to find the main CADisplay', runtime_string_captured=False),
        'Distinguish actual original assertion-reference disassembly from a runtime log')
require(d['native_4k_mmu_observed'] and d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
        d['owner_root_binding_audit']['boot_root_accepted'] and d['owner_boot_manifest']['status'] == 0 and
        d['actual_root_composition']['_native_owner_cache_native_union'] == 1 and 'owner_cache_carrier' not in d and
        not s['functional_ipados_ui_demonstrated'] and not s['original_files_modified'], 'No code tampering, carrier exception or functional UI claim')
print('PASS: actual EL0 FrontBoard display-monitor BRK, through SpringBoard framework, matched to unchanged cache instructions and symbols')
print('Open display assertion: failed to find the main CADisplay; no framebuffer service or functional UI success claimed')
