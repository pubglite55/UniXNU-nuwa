#!/usr/bin/env python3
"""Qualify the GOP-backed legacy display registration and client boundary.

The retained boot registers the real original-family display service, maps
the actual 800x600 QEMU GOP, connects a real client and keeps SpringBoard
alive. It does not submit a swap or present a frame; the QEMU screen still
shows the firmware boot menu. This is not a desktop or hardware result.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'build/darwinboot-armdt-display/gdb-stop.json'
SCREEN = ROOT / 'build/darwinboot-armdt-display/screen.png'
CHECKPOINT = ROOT / 'build/armdt-platform/display-client.json'

report = json.loads(REPORT.read_text())
display = report.get('native_legacy_display')
if not display:
    raise SystemExit('Missing actual legacy display observation')
expected = {
    'stage': 10,
    'meta_status': 0,
    'init_result': 1,
    'start_result': 1,
    'probe_match': 1,
    'parent_match': 1,
    'surface_status': 0,
    'surface_found': 1,
    'gop_width': 800,
    'gop_height': 600,
    'registration_calls': 1,
    'dt_attached': 1,
    'unit_scale_status': 0,
    'unit_scale_calls': 1,
    'chosen_scale': 1,
    'client_status': 0,
}
for key, value in expected.items():
    if display.get(key) != value:
        raise SystemExit(f'{key} is {display.get(key)!r}, expected {value}')
if display.get('client_calls', 0) < 1:
    raise SystemExit('The registered display has no real client')
if display.get('client_pid', -1) <= 1:
    raise SystemExit('The display client must be a real userspace process')
if not report.get('native_4k_mmu_observed'):
    raise SystemExit('Native 4K must be active')
processes = report.get('process_list') or []
names = {entry['name'] for entry in processes}
for name in ('launchd', 'backboardd', 'SpringBoard'):
    if name not in names:
        raise SystemExit(f'Missing actual process: {name}')
screen = report.get('qemu_screen_capture') or {}
if not screen.get('sha256') or not SCREEN.exists():
    raise SystemExit('Missing the actual QEMU screen capture')
if display.get('swap_validation_calls') != 0 or display.get('transfer_calls') != 0:
    raise SystemExit('This checkpoint is for the no-submission boundary')
properties = report.get('native_legacy_properties') or ''
if 'IOMFB Debug Info' not in properties or 'display-timing' in properties or 'IODisplay' in properties:
    raise SystemExit('Unexpected display service property set')
if report.get('native_legacy_client_class') != 'IOMobileFramebufferUserClient':
    raise SystemExit('The real client must be the original IOMobileFramebufferUserClient')
result = {
    'kernel_sha256': report['kernel_sha256'],
    'display_service_registered': True,
    'display_client_connected': True,
    'display_client_pid': display['client_pid'],
    'display_client_name': next((entry['name'] for entry in processes
                                 if entry['pid'] == display['client_pid']), 'unknown'),
    'gop': [display['gop_width'], display['gop_height']],
    'unit_scale': display['chosen_scale'],
    'process_count': len(processes),
    'springboard_present': 'SpringBoard' in names,
    'backboardd_present': 'backboardd' in names,
    'swap_validation_calls': 0,
    'transfer_calls': 0,
    'presented_generation': display.get('presented_generation'),
    'frame_presented': False,
    'visible_ipados_ui': False,
    'qemu_screen_shows': 'firmware/UniXNU boot menu, not a SpringBoard frame',
    'screen_sha256': screen['sha256'],
    'display_client_class': report.get('native_legacy_client_class'),
    'service_properties_sha256': __import__('hashlib').sha256(
        (report.get('native_legacy_properties') or '').encode()).hexdigest(),
    'service_properties_keys': ['IOMFB Debug Info'],
    'display_role_or_timing_properties_present': False,
    'native_4k_observed': True,
    'qemu_only': True,
    'sheng_hardware_tested': False,
}
CHECKPOINT.parent.mkdir(parents=True, exist_ok=True)
CHECKPOINT.write_text(json.dumps(result, indent=2) + '\n')
print('PASS: real GOP-backed display service and userspace client')
print('PASS: SpringBoard/backboardd alive under native 4K')
print('Open: swap/default-surface/fence submission, GPU composition, visible UI')
