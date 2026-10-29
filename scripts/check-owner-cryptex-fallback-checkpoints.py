#!/usr/bin/env python3
"""Record the genuine failed standard dyld fallback-path experiment."""
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]
base = runpy.run_path(str(ROOT / 'scripts/check-native-ram-data-checkpoints.py'))
require = base['require']
expected = base['base']['candidate']('native-owner-cryptex-files-candidate',
    'e57f643394ee87c83ff292db2469a5897656aafd020b50be62b823025eef0457',
    'f261e44dac494e1060bfcbd233c97988159221f92462c242b77acab7d513f7ec')
d = base['base']['report']('owner-hvf-cryptex-files-first-abort')
require(d['kernel_sha256'] == expected and d['native_4k_mmu_observed'] and not d['bounded_timeout_interrupted'] and
        d['scratch_data']['state']['_native_owner_data_status'] == 0 and d['scratch_data']['state']['_native_owner_data_readonly'] == 0 and
        d['owner_root_binding_audit']['boot_root_accepted'] and d['owner_boot_manifest']['status'] == 0 and
        d['original_amfi_table_owner_observed'] and d['actual_signature_failures'] == base['abort']['actual_signature_failures'],
        'Same genuine owner root, writable Data, original AMFI and native-4K conditions')
reason = bytes.fromhex(d['entry_indirect_memory']['1:20:100']['bytes']).split(b'\0')[0].decode()
require(d['stop_symbol'] == '_abort_with_payload' and d['function_return_stack_matched'] and reason == base['reason'],
        'Standard fallback env must not be reported as resolving the same actual original missing-library abort')
require(d['native_ram_block']['state']['_native_ram_block_writes'] > 0 and
        d['native_ram_block']['state']['_native_ram_block_failures'] == 0, 'Retain real mutable Data I/O')
print('PASS: explicit standard fallback-path experiment preserves the same original missing-library abort; no path fix is claimed')
