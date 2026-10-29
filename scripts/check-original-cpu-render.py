#!/usr/bin/env python3
"""Verify the retained original render scheduling/gate observations, not a UI."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'build/cpu-desktop'
summary = {}
for case in ('software-trace', 'software-gates'):
    path = base / case / 'gdb-stop.json'
    data = json.loads(path.read_text())
    assert data['kernel_sha256'] == 'fdcf9e7621deb9df77798de62615a358fe52450b54f5e4a468d2dd76f7738e18'
    assert data['native_4k_mmu_observed'] and data['original_launchd_main_executed']
    assert data['owner_root_binding_audit']['boot_root_accepted']
    assert data['original_amfi_table_owner_observed'] and not any(data['actual_signature_failures'].values())
    assert set(data['direct_user_commpage_shifts'].values()) == {12}
    assert not data['sheng_hardware_tested'] and not data['functional_ipados_boot_demonstrated']
    observed = data['followed_display_query']
    assert observed['activated_process']['name'] == 'backboardd'
    plan = observed['plan']
    assert plan['original_files_modified'] is False
    sites = {site['name']: site for site in plan['trace_sites']}
    counts, results = {}, {}
    for event in observed['trace_events']:
        name = event['name']; site = sites[name]
        assert event['process']['name'] == 'backboardd' and not int(event['pstate'],16) & 31
        assert int(event['pc'],16) == site['address'] + event['process']['shared_region_slide']
        assert event['entry_bytes'] == site['prefix']
        counts[name] = counts.get(name,0) + 1
        assert counts[name] <= site.get('max_hits',1)
        results.setdefault(name, []).append(int(event['arguments'][0],16))
    assert data['native_legacy_display']['transfer_calls'] == 0
    assert data['native_legacy_display']['guard_slot'] == 0
    assert data['bounded_timeout_interrupted']
    if case == 'software-trace':
        assert counts == {'render_for_time':1, 'display_timer':1}
        assert set(observed['trace_pending']) == {'render_update','software_renderer'}
    else:
        for name in ('can_update_enabled_result','can_update_return','is_ready_return'):
            assert counts[name] == 8 and 1 in results[name]
        assert observed['trace_pending'] == ['render_update']
    summary[case] = dict(evidence_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), events=counts,
                        pending=observed['trace_pending'])
summary.update(original_software_renderer_execution_observed=False, desktop_observed=False, hardware_observed=False)
(base/'verified-observations.json').write_text(json.dumps(summary,indent=2)+'\n')
print('PASS: genuine original EL0 scheduling and enabled/update/ready checks; no software-renderer/frame/desktop claim')
