#!/usr/bin/env python3
"""Read-only closeout for the IMG_2974 correction; never issues device commands."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'build/ufs-root-diagnostics/exec-policy'
TRUST = '7416ca4f8377146626bb284e2133c76bee6cb4e3ee0af5d648b186235a7323a7'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def load(path):
    return json.loads(path.read_text())


def main():
    decision = BASE / 'decision.json'
    decision.write_text(json.dumps(dict(offline_preparation_complete=False, device_action_authorized=False))+'\n')
    release = load(BASE / 'release.json')
    for name, digest in release['source_sha256'].items():
        require(sha(ROOT/name) == digest, 'Changed source: '+name)
    for name, digest in release['evidence_sha256'].items():
        require(sha(ROOT/name) == digest, 'Changed evidence: '+name)
    previous = load(ROOT/'build/ufs-root-diagnostics/va64/release.json')
    ufs = ROOT/'drivers/ShengUfs'
    require(subprocess.check_output(['git','-C',str(ufs),'rev-parse','HEAD'],text=True).strip() ==
            previous['native_ufs_commit'], 'Changed UFS revision')
    for name, digest in previous['source_sha256'].items():
        require(sha(ufs/name) == digest, 'Changed UFS implementation: '+name)
    require(sha(ROOT/release['candidate']) == previous['candidate_sha256'] == release['candidate_sha256'],
            'Kernel candidate changed')
    image = ROOT/release['image']
    require(sha(image) == release['image_sha256'] and image.stat().st_size == release['image_bytes'], 'Wrong image')
    package = load(BASE/'package-audit/report.json')
    for field in ('image_sha256','candidate_sha256','embedded_kernel_sha256'):
        require(package[field] == release[field], 'Wrong package '+field)
    old_package = load(ROOT/'build/ufs-root-diagnostics/va64/package-audit/report.json')
    for field in ('config_sha256','data_seed_sha256','boot_args','root_uuid','owned_memory'):
        require(package[field] == old_package[field], 'Changed configuration: '+field)
    require(package['original_trust_cache_sha256'] == TRUST and
            package['patch_reproduction'] == 'byte-for-byte match', 'Missing exact original trust/renderer')
    negative = load(BASE/'no-trust/gdb-stop.json')
    positive = load(BASE/'original-trust/gdb-stop.json')
    require(negative['exec_policy_refusal'] == dict(process='launchd',namespace=9,code=8,description='none') and
            not negative['bounded_timeout_interrupted'], 'Missing genuine absent-trust refusal')
    entry = positive['followed_user_entry']
    require(entry['observed'] and int(entry['pstate'],16)&31 == 0 and
            entry['entry_bytes'] == 'e00300911fec7c921d0080d21e0080d2' and
            positive['trust_cache_bundle_sha256'] == TRUST, 'Original dyld EL0 entry not observed')
    for result in (negative, positive):
        require(result['kernel_sha256'] == release['candidate_sha256'] and result['qemu_accelerator']=='tcg' and
                not result['offline_qemu_vmm_present_declared'] and result['original_amfi_table_owner_observed'] and
                result['owner_root_binding_audit']['boot_root_accepted'] and
                result['native_virtio_integrity']['_native_virtio_integrity_failures']==0,
                'Root/AMFI/comparison evidence mismatch')
        tcr=int(result['system_registers']['TCR_EL1'],16)
        require((tcr>>14&3)==0 and (tcr>>30&3)==2, 'CPU not native 4K')
    for name, count in [('renderer-exec',10),('renderer-ufs',28)]:
        r=load(BASE/name/'report.json')
        require(len(r['matched_lines'])==count and r['renderer_bytes']<=2608 and
                not r['hardware_or_xnu_boot_qualified'], 'Renderer incomplete: '+name)
    require('PASS:' in (BASE/'trust-refusal.log').read_text(), 'Missing changed-cache refusal')
    require(all(r['refused'] and r['stale_report_removed'] for r in load(BASE/'package-refusals.json')),
            'Package refusal failed')
    extended=load(BASE/'original-trust-180/gdb-stop.json')
    require(extended['kernel_sha256']==release['candidate_sha256'] and
            extended['trust_cache_bundle_sha256']==TRUST, 'Wrong extended observation')
    decision.write_text(json.dumps(dict(offline_preparation_complete=True, required_offline_items_remaining=[],
        release_sha256=sha(BASE/'release.json'),image_sha256=release['image_sha256'],
        device_action_authorized=False,boot_sent=False,hardware_success=False,
        original_dyld_el0_observed_offline=True,
        original_launchd_main_observed_offline=extended.get('original_launchd_main_executed',False),
        extended_observation_timeout=extended['bounded_timeout_interrupted'],
        ufs_smmu_mode='unchanged physical bypass',gpu_4k_qualified=False,production_ipados_ready=False),indent=2)+'\n')
    print('PASS: original-trust batch complete; required offline items remaining: 0; no device operation')


if __name__=='__main__':
    main()
