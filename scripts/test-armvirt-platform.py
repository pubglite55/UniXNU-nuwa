#!/usr/bin/env python3
"""Check actual native 4K platform discovery and rejection of an unmatched DT."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check-existing', action='store_true')
args = parser.parse_args()
positive = ROOT / 'build/darwinboot-armvirt'
negative = ROOT / 'build/darwinboot-armvirt-unmatched'
if not args.check_existing:
    command = [sys.executable, ROOT / 'scripts/probe-darwinboot-xnu.py', '--armvirt', '--require-crypto14']
    subprocess.run([*command, '--output', positive, '--break-symbol',
                    '__ZN15ArmVirtPlatform9configureEP9IOService', '--finish-function'], check=True)
    subprocess.run([*command, '--output', negative, '--negative-platform-match'], check=True)
good = json.loads((positive / 'gdb-stop.json').read_text())
bad = json.loads((negative / 'gdb-stop.json').read_text())
if good['kernel_sha256'] != bad['kernel_sha256']:
    raise SystemExit('Platform comparison must use the same kernel')
for report in (good, bad):
    if not report['native_4k_mmu_observed'] or not report['crypto14_initialization_observed']:
        raise SystemExit('Native 4K and real crypto initialization must precede platform matching')
if (int(good['x0'], 16) != 1 or good['pc'] != good.get('function_return_target')
        or good['armvirt_globals']['_armvirt_platform_configured'] != 1
        or good['armvirt_globals']['_armvirt_platform_cpu_count'] != 1
        or good['armvirt_globals']['_armvirt_platform_bus_count'] != 1):
    raise SystemExit('The real platform did not successfully publish its CPU and bus nubs')
reason = bad['argument_memory'].get('x0', '')
if 'Unable to find driver for this platform' not in reason or any(bad['armvirt_globals'].values()):
    raise SystemExit('Unmatched platform must retain the real missing-driver failure')
result = {'kernel_sha256': good['kernel_sha256'], 'platform_configure_returned_true': True,
          'cpu_nubs': 1, 'bus_nubs': 1, 'total_children': good['armvirt_globals']['_armvirt_platform_child_count'],
          'unmatched_platform_refused': True, 'native_4k_observed': True,
          'cpu_interrupt_timer_drivers_proven': False, 'ipados_userspace_boot_demonstrated': False}
(ROOT / 'build/armvirt-platform/test-report.json').write_text(json.dumps(result, indent=2) + '\n')
print('PASS: actual platform configure/CPU+bus nubs and unmatched-DT refusal, native 4K retained')
