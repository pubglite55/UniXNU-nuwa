#!/usr/bin/env python3
"""Validate the frozen post-IMG_2973 UFS release without USB or repeated tests.

This consumes a recorded release manifest; it cannot approve changed sources,
replace hardware evidence, authorize a boot, or qualify GPU translation.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'build/ufs-root-diagnostics/va64'
UFS = ROOT / 'drivers/ShengUfs'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path):
    return json.loads(path.read_text())


def main():
    output = BASE / 'decision.json'
    output.write_text(json.dumps(dict(offline_preparation_complete=False,
        device_action_authorized=False, status='checking')) + '\n')
    release = load(BASE / 'release.json')
    for name, digest in release['evidence_sha256'].items():
        require(sha(ROOT / name) == digest, 'Changed evidence: ' + name)
    for name, digest in release['source_sha256'].items():
        require(sha(UFS / name) == digest, 'Changed driver source: ' + name)
        require((UFS / name).read_bytes() == subprocess.check_output(
            ['git', '-C', str(UFS), 'show', release['native_ufs_commit'] + ':' + name]),
            'Driver differs from recorded revision: ' + name)
    require(subprocess.check_output(['git','-C',str(UFS),'status','--porcelain'],text=True) == '',
            'Driver checkout is dirty')
    image = ROOT / release['image']
    candidate = ROOT / release['candidate']
    require(image.stat().st_size == release['image_bytes'] and sha(image) == release['image_sha256'],
            'Wrong frozen boot image')
    require(sha(candidate) == release['candidate_sha256'], 'Wrong candidate')
    old = load(ROOT / 'build/ufs-root-diagnostics/closeout/decision.json')
    for name, digest in old['evidence_sha256'].items():
        require(sha(ROOT / 'build/ufs-root-diagnostics' / name) == digest, 'Historical evidence changed: ' + name)
    require(old['offline_preparation_complete'] and not old['required_offline_items_remaining'],
            'Historical closeout incomplete')
    retained = load(BASE / 'retained-evidence.json')
    for name, digest in retained['unchanged_production_sha256'].items():
        require(sha(UFS / name) == digest, 'Retained evidence source changed: ' + name)
    previous = subprocess.check_output(['git','-C',str(UFS),'show',
        retained['previous_production_revision'] + ':NativeUfs.cpp'], text=True)
    current = (UFS / 'NativeUfs.cpp').read_text()
    def allocator(text):
        return text.split('  gHost.dma = ',1)[1].split('  uint32_t report[3]',1)[0]
    require(allocator(previous) == allocator(current), 'Actual XNU allocation evidence cannot be retained')
    arm64 = load(BASE / 'arm64/report.json')
    for name, digest in arm64['source_sha256'].items():
        require(sha(UFS / name) == digest, 'ARM64 observation source changed: ' + name)
    require(len(arm64['results']) == 5 and all(r['passed'] for r in arm64['results']), 'ARM64 cases incomplete')
    require('PASS: SMMU geometry/conflicts, VA64 high-DMA regression' in
            (BASE / 'host/SmmuTakeover.log').read_text(), 'SMMU tests failed')
    require('-Werror build and actual ARM64/iOS 17 object audit passed' in
            (BASE / 'crossbuild.log').read_text(), 'Strict build failed')
    prelink = load(candidate.with_suffix('.json'))
    original = load(ROOT / 'build/xnu-prelink/native-owner-stage5-candidate.json')
    require(len(prelink['original_executable_sha256']) == 29 and
            prelink['original_executable_sha256'] == original['original_executable_sha256'],
            'Original executable components changed')
    observed = load(BASE / 'amfi-tcg/gdb-stop.json')
    require(observed['kernel_sha256'] == release['candidate_sha256'] and
            not observed['bounded_timeout_interrupted'] and int(observed['pc'],16) == 0xfffffff004aaeb54,
            'Wrong actual XNU checkpoint')
    pmgr = load(BASE / 'amfi-tcg/pmgr-checked.json')
    require(pmgr['kernel_sha256'] == release['candidate_sha256'] and pmgr['amfi_lookup_qualified'] and
            pmgr['accelerator'] == 'tcg', 'Wrong AMFI validation')
    tcr = int(pmgr['tcr_el1'],16)
    require((tcr >> 14 & 3) == 0 and (tcr >> 30 & 3) == 2, 'Active CPU translation is not 4K')
    package = load(BASE / 'package-audit/report.json')
    for field in ('image_sha256','candidate_sha256','embedded_kernel_sha256'):
        require(package[field] == release[field], 'Package identity differs: ' + field)
    require(package['patch_reproduction'] == 'byte-for-byte match', 'Kernel patch not reproduced')
    previous_package = load(ROOT / 'build/ufs-root-diagnostics/publication/final-package-audit/report.json')
    for field in ('data_seed_sha256','config_sha256','boot_args','root_uuid','owned_memory'):
        require(package[field] == previous_package[field], 'Unexpected configuration change: ' + field)
    # Packaging deliberately generates fresh entropy. The recorded comparison
    # of both embedded ADTs must contain only this 64-byte property change.
    changes = load(BASE / 'adt-diff.json')
    require(len(changes) == 1 and changes[0]['node'] == '/device-tree/chosen' and
            changes[0]['key'] == 'random-seed' and
            len(bytes.fromhex(changes[0]['old'])) == len(bytes.fromhex(changes[0]['new'])) == 64,
            'Unexpected ADT difference')
    result = dict(offline_preparation_complete=True, required_offline_items_remaining=[],
        release_sha256=sha(BASE/'release.json'), checker_sha256=sha(Path(__file__)),
        native_ufs_commit=release['native_ufs_commit'], image_sha256=release['image_sha256'],
        scope='One continuous UFS diagnostic RAM boot, following IMG_2973',
        device_action_authorized=False, boot_sent=False, hardware_success=False,
        cpu_4k_observation='Actual XNU in TCG; prior device TCR retained separately',
        ufs_smmu_mode='Physical bypass; VA64 context readback required; no page tables',
        gpu_4k_qualified=False, production_ipados_ready=False,
        retained_tests='Unchanged queue/commands/GPT/verification/publication/renderer and historical XNU allocator',
        new_tests='SMMU register fixture, ARM64 command cases, strict build, actual XNU AMFI, exact final package')
    output.write_text(json.dumps(result,indent=2)+'\n')
    print('PASS: frozen VA64 release; required offline items remaining: 0; no hardware command sent')


if __name__ == '__main__':
    main()
