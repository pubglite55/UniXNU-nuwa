#!/usr/bin/env python3
"""Require a real allocated PGZ secondary-page object falsely refused before the fix."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def require(value, text):
    if not value: raise SystemExit(text)
p = ROOT / 'build/xnu-prelink/native-owner-pgz-legacy-probe-candidate'
plan = json.loads(p.with_suffix('.json').read_text())
require(plan['native_sha256'] == 'bd62a6409a7ba85849dc8d5bcfe844dcd8d92308d56ca1500ebebe0a9b38e066' and
        hashlib.sha256(p.with_suffix('.macho').read_bytes()).hexdigest() == plan['candidate_sha256'] ==
        '855faea2c3dea3e363615283415c1af2b9eec7de4997e51f292e84c91cfa5f27', 'Exact pre-fix probe kernel')
d = json.loads((ROOT / 'build/darwinboot-owner-hvf-pgz-legacy-positive/gdb-stop.json').read_text())
a = d['actual_zone_pgz_probe']
require(d['kernel_sha256'] == plan['candidate_sha256'] and d['native_4k_mmu_observed'] and
        not d['bounded_timeout_interrupted'] and d['stop_symbol'] == '_panic' and
        a['case'] == 1 and a['stage'] == 2 and a['expected_zone'] == a['zone'] and
        a['metadata'] >> 12 == 10 and a['metadata'] & 1023 == a['zone'] and
        a['backing'] != a['alias'] == a['argument'] and a['backing'] & 4095 == a['alias'] & 4095 and
        (a['alias'] & 4095) + 192 <= 4096 and d['argument_memory']['x0'].startswith(
            'metadata %p corresponding to addr %p being freed to zone') and
        'chunk len greater than max' in d['argument_memory']['x0'],
        'Actual live correct-zone PGZ object must reproduce the earlier false refusal; no timeout or invalid fixture')
print('PASS: pre-fix native-4K kernel genuinely rejects an allocated correct-zone PGZ object after its ordinary backing passed alignment')
