#!/usr/bin/env python3
"""Qualify the usermanagerd session-setup checkpoint with the provisioned Data.

The retained run is a bounded QEMU/HVF boot of the 29-component candidate with
the empty directory skeleton and the genuine -apfs_shared_datavolume argument.
It proves the original user-management stack creates its own personas and
foreground user; it does not prove a SpringBoard/backboardd launch, a display,
a desktop or any hardware result.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'build/darwinboot-armdt-bootdata/gdb-stop.json'
CHECKPOINT = ROOT / 'build/armdt-platform/data-provision-checkpoint.json'

report = json.loads(REPORT.read_text())
if not report.get('native_4k_mmu_observed'):
    raise SystemExit('Native 4K must be active')
data = (report.get('scratch_data') or {}).get('state', {})
if data.get('_native_owner_data_status') != 0 or data.get('_native_owner_data_readonly') != 0:
    raise SystemExit('The Data volume must be writable through the real backend')
writes = []
for event in report.get('syscall_events', []):
    if event.get('number') in (4, 397) and event.get('write_bytes'):
        try:
            writes.append(bytes.fromhex(event['write_bytes']).decode('utf-8', 'replace'))
        except ValueError:
            continue
text = '\n'.join(writes)
required = (
    'MKB_INIT: No system keybag loaded.',
    '****** DONE MKB_INIT ****',
    'Creating New Primary Session with uid 501',
    'Created default user 501',
    'Loading foreground user 501',
    'Created Personal Persona Successfully',
    'Created System Persona Successfully',
)
for item in required:
    if item not in text:
        raise SystemExit(f'Missing original usermanagerd output: {item}')
if 'FATAL KEYBAG ERROR' in text or 'REBOOTING INTO RECOVERY MODE' in text:
    raise SystemExit('The run still took the fatal keybag/recovery path')
if report.get('critical_process_exit'):
    raise SystemExit('A critical userspace process still exits')
last = max((event.get('elapsed_seconds', 0) for event in report.get('syscall_events', [])), default=0)
result = {
    'kernel_sha256': report['kernel_sha256'],
    'data_fixture_sha256': (report.get('scratch_data') or {}).get('input', {}).get('sha256'),
    'data_writable': True,
    'keybag_no_system_keybag_allowlist': True,
    'usermanagerd_created_sessions': True,
    'foreground_user': 501,
    'personas_created': ['System', 'Default', 'Personal'],
    'capture_last_seconds': last,
    'capture_exhausted': bool(report.get('syscall_log_exhausted')),
    'springboard_observed_in_capture': 'SpringBoard' in text,
    'backboardd_observed_in_capture': 'backboardd' in text,
    'native_4k_observed': True,
    'qemu_only': True,
    'sep_or_system_keybag_present': False,
    'functional_ipados_boot_demonstrated': False,
}
CHECKPOINT.parent.mkdir(parents=True, exist_ok=True)
CHECKPOINT.write_text(json.dumps(result, indent=2) + '\n')
print('PASS: provisioned Data reaches original usermanagerd session setup')
print('Open: SpringBoard/backboardd, display/GPU, UI; capture may end before later processes')
