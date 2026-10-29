#!/usr/bin/env python3
"""Qualify original launchd mount phase arguments and its genuine missing input."""
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]
base = runpy.run_path(str(ROOT / 'scripts/check-original-launchd-integrity-checkpoints.py'))
require = base['require']
spawn, output = [json.loads((ROOT / ('build/darwinboot-owner-hvf-' + name) / 'gdb-stop.json').read_text())
                 for name in ('mount-spawn', 'mount-output')]
for d in (spawn, output):
    require(d['kernel_sha256'] == base['positive']['kernel_sha256'] and not d['bounded_timeout_interrupted'] and
            d['owner_root_binding_audit']['boot_root_accepted'] and d['original_amfi_table_owner_observed'] and
            d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0), 'Same genuine native-4K original OS/security path')
require(spawn['stop_symbol'] == '_posix_spawn' and spawn['function_return_stack_matched'] and int(spawn['x0'], 16) == 0 and
        spawn['spawn_parent_is_initproc'] and spawn['entry_string_events'][-1]['value'] == '/sbin/mount' and
        bytes.fromhex(spawn['entry_indirect_memory']['1:0:4']['bytes']) == b'\x03\0\0\0', 'Real PID-1 parent successfully spawns mount PID 3')
vector = spawn['entry_user_vectors']['1:18:10']
require(vector['terminated'] and [x['value'] for x in vector['values']] == ['mount', '-P', '1'] and
        not any(x['truncated'] for x in vector['values']), 'Capture complete actual mount phase-1 argv')
require(output['critical_process_exit'] == dict(process='mount[3] exited', signal=0, status=66, cs_status='') and
        output['syscall_start_event']['pc'] == '0xfffffff00bcb312c' and not output['syscall_log_exhausted'], 'Retain actual critical exit and bounded phase-selected observations')
writes = [bytes.fromhex(e['write_bytes']).decode(errors='replace') for e in output['syscall_events']
          if e['number'] in (4, 397) and 'write_bytes' in e and not e['write_bytes'].startswith('E')]
require(any('data volume missing, but not required in env: 0' in x for x in writes) and
        any('failed to get boot-manifest-hash' in x for x in writes) and
        any('failed to get boot manifest hash - No such file or directory' in x for x in writes),
        'Actual original stderr identifies missing manifest hash; do not guess that missing Data is the current cause')
print('PASS: original launchd PID 1 spawns mount -P 1 as PID 3; genuine missing boot-manifest-hash causes exit 66')
