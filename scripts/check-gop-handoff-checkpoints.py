#!/usr/bin/env python3
"""Qualify actual UEFI GOP -> boot_args -> native-4K XNU PE video handoff."""
import hashlib
import json
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
base = runpy.run_path(str(ROOT / 'scripts/check-native-arch-timer-checkpoints.py'))
require = base['require']
elf = '54e699b71025e66b97033c4836d746ae8dd5b48963001a62e587be30b3a477e9'
require(hashlib.sha256((ROOT / 'build/DarwinBoot/DEBUG_CLANGPDB/AARCH64/DarwinBoot.efi').read_bytes()).hexdigest() == elf,
        'Exact tested loader binary')
for name, present in (('gop-native-launchd-main', True), ('video-headless-native-main', False)):
    d = json.loads((ROOT / ('build/darwinboot-owner-hvf-' + name) / 'gdb-stop.json').read_text())
    v = d['actual_boot_video']
    expected = dict(physical_base=2088370176, display=1, row_bytes=3200, width=800, height=600, depth=32) if present else {
        k: 0 for k in ('physical_base', 'display', 'row_bytes', 'width', 'height', 'depth')}
    require(d['kernel_sha256'] == base['expected'] and d['stop_symbol'] == 'original-launchd-main' and
            d['original_launchd_main_executed'] and d['followed_main_entry']['first_instruction_completed'] and
            d['native_4k_mmu_observed'] and d['direct_user_commpage_shifts'] == {'fffff4025:1': 12, 'fffff4037:1': 12} and
            v['qemu_ramfb_attached'] == present and v['darwinboot_driver_sha256'] == elf and
            v['boot_args'] == expected and v['pe_video'] == dict(zip(
                ('v_baseAddr', 'v_rowBytes', 'v_width', 'v_height', 'v_depth', 'v_display'),
                (expected['physical_base'], expected['row_bytes'], expected['width'], expected['height'], expected['depth'], expected['display']))),
            'Actual firmware resource must propagate through actual boot args and XNU PE state; headless stays zero')
    layout = v['compiled_layout']
    require(layout['state_size'] == 176 and layout['video'] == 8 and layout['boot_args'] == 160 and
            layout['object_sha256'] == 'ba3cadd9293005dd74c033b91839d00a6c658044cf7db5650d3e505dc22eb365' and
            d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
            d['owner_boot_manifest']['status'] == 0 and d['owner_root_binding_audit']['boot_root_accepted'] and
            not v['native_mobile_framebuffer_qualified'] and not d['functional_ipados_boot_demonstrated'],
            'Compiler-derived layout, actual code/root integrity and honest display scope')
for directory, text in (('darwinboot-test', 'boot_args, RAMDisk, TrustCache, zero-fill and MMU-off entry'),
                        ('darwinboot-test-gop', 'actual GOP boot video after ExitBootServices')):
    log = (ROOT / 'build' / directory / 'qemu.clean.log').read_text()
    require('DARWINBOOT-FIXTURE: ' + text + ' PASS' in log and
            '33 rejected requests; firmware retained PASS' in log and
            '8 malformed/unsupported GOP field sets refused PASS' in log and 'ASSERT' not in log,
            'Bounded loader fixture and same-parser invalid field controls must pass')
for mode in ('debug', 'release'):
    log = (ROOT / ('build/darwinboot-video-' + mode + '-build.log')).read_text()
    require('-Werror' in log and '- Done -' in log and not re.search(r'error:|error [A-Z0-9]+:', log),
            'Both actual warning-as-error builds must complete')
print('PASS: actual GOP 800x600/BGRX32 and headless zeros propagate into native-4K XNU PE state')
print('PASS: original launchd main, DEBUG/RELEASE builds and eight malformed-field refusals; mobile framebuffer/UI remain open')
