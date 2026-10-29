#!/usr/bin/env python3
"""Check real CPU registration, timer dispatch, missing-GIC refusal and 4K commpages."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check-existing', action='store_true')
args = parser.parse_args()
start_symbol = '__ZN6ArmCpu5startEP9IOService'
cases = {
    'start': ('darwinboot-pthread-armcpu-start', ['--break-symbol', start_symbol, '--finish-function']),
    'timer': ('darwinboot-armcpu-timer', ['--break-symbol', '_rtclock_intr', '--finish-function']),
    'missing_gic': ('darwinboot-armcpu-missing-gic', ['--missing-gic', '--break-symbol', start_symbol, '--finish-function']),
    'commpage': ('darwinboot-armcpu-bsd-commpage', ['--break-symbol', '_bsd_init', '--check-commpage']),
}
reports = {}
for name, (directory, options) in cases.items():
    output = ROOT / 'build' / directory
    if not args.check_existing:
        subprocess.run([sys.executable, ROOT / 'scripts/probe-darwinboot-xnu.py', '--armvirt', '--armcpu',
                        '--require-crypto14', '--output', output, *options], check=True)
    reports[name] = json.loads((output / 'gdb-stop.json').read_text())
if len({report['kernel_sha256'] for report in reports.values()}) != 1:
    raise SystemExit('CPU checks must use the same kernel')
for report in reports.values():
    if (not report['native_4k_mmu_observed'] or not report['crypto14_initialization_observed']
            or report.get('bounded_timeout_interrupted')):
        raise SystemExit('Native 4K, real crypto and reached milestones are required')
    pthread = report['pthread_globals']
    if (pthread['_source_pthread_status'] != 0 or not pthread['_pthread_functions']
            or not pthread['_pthread519_pthread_kern']):
        raise SystemExit('Real pthread registration and callback exchange are required')
for name in ('start', 'timer', 'missing_gic'):
    if reports[name]['pc'] != reports[name].get('function_return_target'):
        raise SystemExit(f'{name} did not return to its actual caller')
start = reports['start']
if int(start['x0'], 16) != 1:
    raise SystemExit('CPU start did not return true')
for name in ('start', 'timer'):
    cpu = reports[name]['armcpu_globals']
    if any(cpu[key] != 1 for key in ('_armcpu_registered', '_armcpu_gic_ready', '_gCPUsRunning')):
        raise SystemExit(f'{name}: real CPU/GIC initialization incomplete')
if reports['timer']['armcpu_globals']['_armcpu_timer_interrupts'] < 1:
    raise SystemExit('No real timer interrupt dispatched through rtclock_intr')
bad = reports['missing_gic']
if int(bad['x0'], 16) != 0 or any(bad['armcpu_globals'].values()):
    raise SystemExit('Absent GIC must reject start without registering a running CPU')
if reports['commpage']['commpage_user64_shifts'] != {'_commpage_rw_addr': 12, '_commpage_kernel_ro_addr': 12}:
    raise SystemExit('Both real user64 commpage aliases must advertise native 4K')
result = {'kernel_sha256': start['kernel_sha256'], 'cpu_start_returned_true': True,
          'real_pthread_registration': True, 'rtclock_intr_returned': True,
          'timer_interrupts': reports['timer']['armcpu_globals']['_armcpu_timer_interrupts'],
          'missing_gic_refused': True, 'native_4k_observed': True,
          'legacy_and_ro_commpage_user64_shifts': [12, 12],
          'ipi_delivery_verified': False, 'hardware_boot_demonstrated': False,
          'ipados_userspace_boot_demonstrated': False}
(ROOT / 'build/armcpu/test-report.json').write_text(json.dumps(result, indent=2) + '\n')
print('PASS: real CPU/pthread registration, timer dispatch/return, missing-GIC refusal, native 4K commpages')
