#!/usr/bin/env python3
"""Qualify two read-only APFS data mounts and preserve genuine PMGR refusal."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
import native_prelink as np


def require(value, message):
    if not value:
        raise SystemExit(message)


def report(name):
    return json.loads((ROOT / 'build' / name / 'gdb-stop.json').read_text())


def native(d):
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'], 'Active native 4K is required')
    require(d['virtio_block_input']['read_only'] and d['virtio_extra_block_input']['read_only'],
            'Both real inputs must be read-only')
    require(d['virtio_block_input']['source_sha256'] ==
            '3f99b859c9728379110b66657c7b15285bcb1925ad8b5726542e2cdcf8b1028d', 'Original OS identity differs')
    require(d['virtio_extra_block_input']['first_sector_sha256'] ==
            '42b1178767bb27611cd1836cdd5779c48bfca8a3e719ec06dc4c8ef78d5e6387', 'Original raw container sector differs')


discovery = report('darwinboot-two-volume-discovery')
mounts = report('darwinboot-apfs-component-mounts')
refusal = report('darwinboot-original-apfs-cache-loader')
for d in (discovery, mounts, refusal):
    native(d)
    require(d['kernel_sha256'] == '8db7506164cb7772c6af3e8bd21b4a9ee3a951c5c611550deae923ed1558628f',
            'These checkpoints require the exact unchanged candidate')
for d in (discovery, mounts):
    properties = {}
    for e in d['registry_string_events']:
        properties.setdefault(e['entry'], {})[e['key']] = e['value']
    names = {e['UUID']: e['BSD Name'] for e in properties.values() if 'UUID' in e and 'BSD Name' in e}
    require(names.get('04769D26-2CA0-4825-B443-E2E5F88300F2') == 'disk3s1' and
            names.get('8846FE78-2910-4297-AF97-D59BB6F8FC16') == 'disk2s1',
            'Use the actual same-entry UUID/BSD publication, not enumeration guesses')
    require(d['native_user_4k_abi_observed'], 'The own process must retain its actual 4K ABI')
r = mounts['apfs_launchd_component']
require(r['stage'] == 5 and all(r[k] == 0 for k in ('mkdir', 'os_mount', 'cache_mount', 'chroot', 'chdir')) and
        all(r[k] >> 29 & 1 == 0 for k in ('mkdir_nzcv', 'os_mount_nzcv', 'cache_mount_nzcv', 'chroot_nzcv', 'chdir_nzcv')),
        'All five actual syscalls must succeed')
require(not refusal['bounded_timeout_interrupted'] and not refusal.get('followed_user_entry') and
        not refusal['original_dyld_cache_loader_returned'] and not refusal['root_authentication_solved'],
        'The actual AMFI refusal must remain a refusal before original dyld')
require('AMFI: No PMGR?' in refusal['argument_memory']['x0'], 'Preserve the actual original AMFI panic')
require(refusal['kernel_observations']['_native_virtio_read_requests'] == 305 and
        refusal['kernel_observations']['_native_virtio_read_failures'] == 0 and
        refusal['kernel_observations']['_cs_validate_page_bad_hash'] == 0 and
        refusal['kernel_observations']['_cs_validate_page_no_hash'] == 0, 'Real storage/signature state differs')
require([e['number'] for e in refusal['syscall_events']][-5:] == [167, 167, 61, 12, 59],
        'The real data mounts/chroot/chdir/exec sequence is required')
plan = json.loads((ROOT / 'build/xnu-prelink/native-apfs-data-candidate.json').read_text())
kernel = (ROOT / 'build/xnu-prelink/native-apfs-data-candidate.macho').read_bytes()
require(hashlib.sha256(kernel).hexdigest() == refusal['kernel_sha256'], 'Candidate identity mismatch')
meta = np.macho(kernel)
original = (ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed').read_bytes()
old = np.macho(original)
require(hashlib.sha256(original).hexdigest() == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7',
        'Use the actual ordinary-ARM64 supplied kernel')
for extent in plan['extents']:
    if extent['segment'] != '__TEXT_EXEC':
        continue
    va, size = extent['va'], extent['size']
    newat = np.backed_offset(meta['segments'], va, size, len(kernel))
    oldat = np.backed_offset(old['segments'], va - plan['slide'], size, len(original))
    require(kernel[newat:newat + size] == original[oldat:oldat + size], 'Original executable bytes changed')
lr = int(refusal['x30'], 16)
require(any(e['module'] == 'com.apple.driver.AppleMobileFileIntegrity' and e['segment'] == '__TEXT_EXEC' and
            e['va'] <= lr < e['va'] + e['size'] for e in plan['extents']), 'Panic caller must be genuine original AMFI')
print('PASS: actual UUID discovery, both read-only APFS mounts/chroot and genuine original AMFI PMGR refusal')
print('Original dyld/cache loading, production root authentication and hardware remain unqualified')
