#!/usr/bin/env python3
"""Reproduce and qualify the real shared-Data keybag path offline.

This runs the exact 29-component candidate with a writable APFS Data fixture
and the genuine Apple boot argument `-apfs_shared_datavolume`. It verifies
that keybagd takes its no-system-keybag allow-list path instead of the fatal
recovery path, and records the next real userspace input failure. QEMU/HVF
only: no sheng hardware, SEP, keybag, UI or desktop is claimed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'build/xnu-prelink/native-owner-armdt-nubs-candidate'
DATA_SEED = ROOT / 'build/offline-renderbox-present-2/compiler-data-32.cdr'
DATA = ROOT / 'build/offline-renderbox-present-2/compiler-data-32-keybags.cdr'
OUTPUT = ROOT / 'build/darwinboot-armdt-keybag-bypass'
CHECKPOINT = ROOT / 'build/armdt-platform/keybag-bypass.json'

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check-existing', action='store_true')
parser.add_argument('--output', type=Path, default=OUTPUT)
args = parser.parse_args()

if not BASE.with_suffix('.macho').exists() or not BASE.with_suffix('.json').exists():
    raise SystemExit('Missing the native owner ArmDT candidate')
plan = json.loads(BASE.with_suffix('.json').read_text())
if hashlib.sha256(BASE.with_suffix('.macho').read_bytes()).hexdigest() != plan['candidate_sha256']:
    raise SystemExit('Candidate report does not identify this exact image')


def ensure_data_fixture():
    if DATA.exists():
        return
    shutil.copyfile(DATA_SEED, DATA)
    mount = ROOT / 'build/offline-renderbox-present-2/data-keybags-mount'
    mount.mkdir(parents=True, exist_ok=True)
    info = plistlib.loads(subprocess.check_output(
        ['hdiutil', 'attach', '-nobrowse', '-owners', 'off', '-mountpoint', str(mount),
         str(DATA), '-plist']))
    device = info['system-entities'][0]['dev-entry']
    try:
        (mount / 'keybags/backup').mkdir(parents=True, exist_ok=True)
    finally:
        subprocess.run(['hdiutil', 'detach', device], check=True, capture_output=True)
        mount.rmdir()


def run_probe():
    if args.output.exists():
        raise SystemExit(f'Preserve the existing observation: {args.output}')
    ensure_data_fixture()
    command = [
        sys.executable, str(ROOT / 'scripts/probe-darwinboot-xnu.py'),
        '--kernel', str(BASE.with_suffix('.macho')),
        '--prelink-report', str(BASE.with_suffix('.json')),
        '--output', str(args.output),
        '--virtio-udif-image', '.cache/firmware/target-volumes/044-76040-038.dmg',
        '--virtio-extra-block-image', '.cache/firmware/target-volumes/044-76034-038.dmg',
        '--virtio-mmio-fdt', 'build/virtio-block-fixture/qemu-virt.dtb',
        '--root-match-volume-uuid', '04769D26-2CA0-4825-B443-E2E5F88300F2',
        '--trust-cache', 'build/original-static-system-trust/original-static-system.bundle',
        '--armvirt', '--armdt-platform', '--armcpu', '--qemu-vmm-present',
        '--qemu-accel', 'hvf', '--owned-memory-size', '0x20000000', '--nvram-proxy',
        '--crypto-hash-method', 'sha2-384', '--amfi-platform-only', '--load-apfs',
        '--inspect-owner-root', '--inspect-dyld-flags', '--check-commpage',
        '--skip-initializer-traces', '--timeout', '60',
        '--data-ramdisk', str(DATA),
        '--kernel-extra-args=-apfs_shared_datavolume',
        '--log-syscalls-after', '_posix_spawn',
        '--log-syscall-number', '4', '--log-syscall-number', '397',
        '--log-syscall-number', '1', '--log-syscall-number', '59',
        '--log-syscall-number', '10', '--log-syscall-number', '57',
        '--log-syscall-number', '128', '--log-syscall-number', '136',
    ]
    subprocess.run(command, cwd=ROOT, check=True, timeout=240)


if not args.check_existing:
    run_probe()

report_path = args.output / 'gdb-stop.json'
if not report_path.exists():
    raise SystemExit(f'Missing observation: {report_path}')
report = json.loads(report_path.read_text())
if report['kernel_sha256'] != plan['candidate_sha256']:
    raise SystemExit('Observation is from a different candidate')
if not report.get('native_4k_mmu_observed'):
    raise SystemExit('Native 4K must be active')
data_state = (report.get('scratch_data') or {}).get('state', {})
if data_state.get('_native_owner_data_status') != 0 or data_state.get('_native_owner_data_readonly') != 0:
    raise SystemExit('The Data volume must mount writable through the real backend')
writes = []
for event in report.get('syscall_events', []):
    if event.get('number') in (4, 397) and event.get('write_bytes'):
        try:
            writes.append(bytes.fromhex(event['write_bytes']).decode('utf-8', 'replace'))
        except ValueError:
            continue
text = '\n'.join(writes)
required = (
    'bootarg = 1',
    'MKB_INIT: No system keybag loaded.',
    '****** DONE MKB_INIT ****',
    'usermanagerd',
)
for item in required:
    if item not in text:
        raise SystemExit(f'Missing real keybag/usermanagerd output: {item}')
if 'FATAL KEYBAG ERROR' in text or 'REBOOTING INTO RECOVERY MODE' in text:
    raise SystemExit('The run still took the fatal keybag/recovery path')
if report.get('critical_process_exit'):
    raise SystemExit('A critical userspace process still exits')
result = {
    'kernel_sha256': report['kernel_sha256'],
    'boot_argument': '-apfs_shared_datavolume',
    'keybag_bootarg': 1,
    'no_system_keybag_allowlist': True,
    'recovery_path': False,
    'data_writable': True,
    'usermanagerd_reached': True,
    'next_input': 'persona/session state on the empty Data fixture',
    'native_4k_observed': True,
    'qemu_only': True,
    'sep_or_system_keybag_present': False,
    'springboard_or_backboard_observed': False,
    'ipados_userspace_boot_demonstrated': False,
}
CHECKPOINT.parent.mkdir(parents=True, exist_ok=True)
CHECKPOINT.write_text(json.dumps(result, indent=2) + '\n')
print('PASS: shared-Data bootarg selects the real no-system-keybag allow-list path')
print('PASS: writable Data and usermanagerd reached; no recovery and no fabricated key')
print('Open: persona/session provisioning, SpringBoard/backboardd, display/GPU, hardware')
