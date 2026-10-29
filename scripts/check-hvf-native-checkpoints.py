#!/usr/bin/env python3
"""Qualify HVF native-4K execution, optional DT panic region and actual memory refusal."""
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
    return json.loads((ROOT / ('build/darwinboot-' + name) / 'gdb-stop.json').read_text())


d = report('owner-hvf-cache-shared-region')
candidate = ROOT / 'build/xnu-prelink/native-owner-dt-panic-candidate'
plan = json.loads(candidate.with_suffix('.json').read_text())
kernel = candidate.with_suffix('.macho').read_bytes()
require(hashlib.sha256(kernel).hexdigest() == plan['candidate_sha256'] ==
        'f3611f1aa0a472122196134101237384de931d4d78d6f02d3c7013a63405898d' and plan['native_sha256'] ==
        '926d1e6bc223b12d482e5b48c0e3fd43173108168f54c2e1cb5cf3042f0f8eae' and len(plan['components']) == 15,
        'Require exact original-component mount candidate')
original = (ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed').read_bytes()
require(hashlib.sha256(original).hexdigest() == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7', 'Require supplied target')
old, meta = np.macho(original), np.macho(kernel)
for e in plan['extents']:
    if e['segment'] == '__TEXT_EXEC':
        at = np.backed_offset(meta['segments'], e['va'], e['size'], len(kernel))
        prev = np.backed_offset(old['segments'], e['va'] - plan['slide'], e['size'], len(original))
        require(kernel[at:at + e['size']] == original[prev:prev + e['size']], 'Every original executable extent must remain unchanged')
trust = (ROOT / 'build/original-static-system-trust/original-static-system.bundle').read_bytes()
require(hashlib.sha256(trust).hexdigest() == '7416ca4f8377146626bb284e2133c76bee6cb4e3ee0af5d648b186235a7323a7' and
        struct.unpack_from('<II', trust) == (2, 12), 'Require only the two original trust modules')
second = struct.unpack_from('<I', trust, 8)[0]
require(hashlib.sha256(trust[12:second]).hexdigest() == 'da88460e6e513438d5307e5c526f76497a74754476a24da29f239f0c90120fc2' and
        hashlib.sha256(trust[second:]).hexdigest() == 'd121ba89167e03aafd00fa687c30cd8ebc4ccafd10c1408adb2ba3de12403651',
        'No original trust byte or own code entry may be substituted')
require(d['kernel_sha256'] == plan['candidate_sha256'] and d['qemu_accelerator'] == 'hvf' and
        d['qemu_cpu_model'] == 'host' and d['offline_qemu_vmm_present_declared'] and
        not d['bounded_timeout_interrupted'] and d['trust_cache_bundle_sha256'] == hashlib.sha256(trust).hexdigest(), 'Exact bounded HVF fixture with original trust input')
r = {k: int(v, 16) for k, v in d['system_registers'].items()}
require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and r['SCTLR_EL1'] & 1 and
        r['TTBR0_EL1'] and r['TTBR1_EL1'] and r['CNTFRQ_EL0'] == 24000000 and
        d['kernel_page_globals'] == dict(_PAGE_SHIFT_CONST=12, _page_shift=12, _page_shift_user32=12, _page_size=4096), 'Actual native-4K hardware mappings and runtime globals')
require(d['original_amfi_table_owner_observed'] and d['original_crypto_initialized_observed'] and
        d['original_crypto_table_owner_observed'] and d['owner_root_binding_audit']['boot_root_accepted'] and
        d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80, 'Real original AMFI/crypto and owner root enforcement remain active')
state = d['owner_cache_mount']
require(state['_native_owner_cache_stage'] == 6 and state['_native_owner_cache_status'] == 0 and
        state['_native_owner_cache_mount_status'] == 0 and state['_native_owner_cache_readonly'] == 1 and
        state['_native_owner_cache_authorized'] == state['_native_owner_cache_root_recheck'] == 1 and
        state['_native_owner_cache_selected_device'] == state['_native_owner_cache_mounted_device'] == 0x01000004 and
        state['actual_device_path'] == '/dev/disk2s1', 'Actual authenticated readonly SystemOS mount')
require(d['actual_panic_region'] == dict(_gPanicBase=0, _gPanicSize=0, _panic_info=0), 'No advertised panic region means no mapping or fabricated log')
require(d['dyld_startup_flags'] == dict(_dyld_flags=8, _native_owner_cache_dyld_flags=8, actual_commpage_flags=8) and
        d['native_signature_hash_cache'] == dict(_cs_native4k_hash_cache_version=1, _cs_native4k_full_blocks=61441,
        _cs_native4k_page_checks=76, _cs_native4k_ready_blobs=19), 'Retain original code authentication and native-4K page checks')
require(d['native_virtio_globals']['_native_virtio_read_requests'] == 18537 and
        d['native_virtio_globals']['_native_virtio_read_failures'] == 0 and
        d['native_virtio_integrity']['_native_virtio_verified_blocks'] == 251564 and
        d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0 and
        d['native_virtio_integrity']['_native_virtio_verified_devices'] == 2, 'Actual original media I/O remains authenticated')
require(d['stop_symbol'] == '_panic' and d['argument_memory']['x0'].startswith('memorystatus_jetsam_thread: no victim!') and
        struct.unpack_from('<Q', bytes.fromhex(d['stack_bytes']))[0] == 3272 and
        not d['ipados_userspace_boot_demonstrated'], 'Preserve genuine memory-pressure refusal, no full-boot claim')
folder = ROOT / 'build/darwinboot-owner-hvf-cache-shared-region'
require('owned=0x10000000' in (folder / 'gdb-uart.log').read_text(), 'Actual UEFI loader owns only 256 MiB in this control')
# HVF stopped before full shared-region mapping; the earlier template-address abort is a different failure.
previous = ROOT / 'build/darwinboot-hvf-native-platform-init'
failure = json.loads((previous / 'gdb-failure.json').read_text())
require(failure['kernel_sha256'] == 'cef9ebddda8afc0e407cf933e0bfc97fabb6e754a0a2e3fcf740ef02188a07b3' and
        failure['qemu_accelerator'] == 'hvf' and not failure['checkpoint_observed'] and
        any(int(e['pc'], 16) == 0xfffffff00bf24410 for e in failure['trace_events']) and
        'Assertion failed: (isv)' in (previous / 'gdb-stderr.log').read_text(), 'Keep actual old fixed-panic-region emulator failure distinct')
print('PASS: HVF executes actual native-4K XNU, both authenticated original media and 19 original signature objects')
print('PASS: absent DT panic region remains unmapped; genuine 256-MiB memory-pressure panic is preserved')
print('Full shared-cache mapping, launchd main and bare-metal PMGR remain open')
