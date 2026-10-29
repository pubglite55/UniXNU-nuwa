#!/usr/bin/env python3
"""Qualify owner dyld startup, original cache preflight and genuine PMGR refusal."""
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


positive, missing = (report(name) for name in (
    'owner-cache-shared-region', 'owner-startup-missing-refusal'))
candidate = ROOT / 'build/xnu-prelink/native-owner-dyld-startup-candidate'
plan = json.loads(candidate.with_suffix('.json').read_text())
kernel = candidate.with_suffix('.macho').read_bytes()
require(hashlib.sha256(kernel).hexdigest() == plan['candidate_sha256'] ==
        'cef9ebddda8afc0e407cf933e0bfc97fabb6e754a0a2e3fcf740ef02188a07b3' and plan['native_sha256'] ==
        '6c4a55cadc58e7c680cd8d0c9e67b5f166354ff4149a12078d3f79719870b064' and len(plan['components']) == 15,
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
for d in (positive, missing):
    require(d['kernel_sha256'] == plan['candidate_sha256'] and not d['bounded_timeout_interrupted'] and
            d['trust_cache_bundle_sha256'] == hashlib.sha256(trust).hexdigest(), 'Require exact bounded original-trust candidate')
    regs = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(regs['TCR_EL1'] >> 14 & 3 == 0 and regs['TCR_EL1'] >> 30 & 3 == 2 and regs['SCTLR_EL1'] & 1 and
            regs['TTBR0_EL1'] and regs['TTBR1_EL1'] and d['original_amfi_table_owner_observed'] and
            d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'], 'Require actual native 4K and original AMFI/crypto')
    root = d['owner_root_binding_audit']
    require(root['boot_root_accepted'] and root['_native_owner_root_apple_autherr'] == 80 and
            root['actual_uuid'] == '04769D26-2CA0-4825-B443-E2E5F88300F2', 'Retain separate actual owner root proof and Apple error')
    require(d['native_virtio_globals']['_native_virtio_read_failures'] == 0 and
            d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0, 'No unauthenticated I/O')
    require(d['stop_symbol'] == '_panic' and not d['ipados_userspace_boot_demonstrated'], 'Keep genuine remaining refusal')
state = positive['owner_cache_mount']
require(state['_native_owner_cache_stage'] == 6 and state['_native_owner_cache_status'] == 0 and
        state['_native_owner_cache_mount_status'] == 0 and state['_native_owner_cache_readonly'] == 1 and
        state['_native_owner_cache_authorized'] == 1 and state['_native_owner_cache_root_recheck'] == 1 and
        state['_native_owner_cache_selected_device'] == state['_native_owner_cache_mounted_device'] == 0x01000004 and
        state['actual_device_path'] == '/dev/disk2s1', 'Require actual readonly SystemOS mount and both owner proofs')
require(positive['dyld_startup_flags'] == dict(_dyld_flags=8, _native_owner_cache_dyld_flags=8, actual_commpage_flags=8),
        'Observe bit 3 in actual kernel and commpage state')
require(positive['native_signature_hash_cache'] == dict(_cs_native4k_hash_cache_version=1,
        _cs_native4k_full_blocks=53998, _cs_native4k_page_checks=68, _cs_native4k_ready_blobs=17), 'Pin original whole-file authentication and genuine native-4K page validation')
require(positive['native_virtio_globals']['_native_virtio_read_requests'] == 16305 and
        positive['native_virtio_integrity']['_native_virtio_verified_blocks'] == 220805 and
        positive['native_virtio_integrity']['_native_virtio_verified_devices'] == 2, 'Pin actual verified DMA preflight')
require('AMFI: No PMGR?' in positive['argument_memory']['x0'] and positive['panic_caller_component'] ==
        dict(module='com.apple.driver.AppleMobileFileIntegrity', segment='__TEXT_EXEC', offset='0x1f420'), 'Preserve original AMFI hardware dependency')
# Actual native local symbols identify an asynchronous worker; do not label this as cache file 17 rejection.
import subprocess
symbols = {}
for line in subprocess.check_output(['xcrun', 'nm', '-n', candidate.with_suffix('.macho')], text=True).splitlines():
    fields = line.split()
    if len(fields) == 3:
        try: symbols[fields[2]] = int(fields[0], 16)
        except ValueError: pass
returns = {int(frame['lr'], 16) for frame in positive['frame_chain']}
require(all(symbols[name] + offset in returns for name, offset in (
        ('_thread_call_invoke', 0x78), ('_thread_call_thread', 0x220), ('_Call_continuation', 0x44))), 'Require actual thread-call worker stack')
require(not any(e.get('symbol') == '_shared_region_map_and_slide_2_np' for e in positive['trace_events']), 'Do not claim full shared-region mapping')
state = missing['owner_cache_mount']
require(missing['dyld_startup_flags'] == dict(_dyld_flags=0, _native_owner_cache_dyld_flags=0, actual_commpage_flags=0) and
        missing['argument_memory']['x0'].startswith('offline owner SystemOS mount failed: %d') and
        struct.unpack_from('<Q', bytes.fromhex(missing['stack_bytes']))[0] == 80 and
        state['_native_owner_cache_stage'] == 1 and state['_native_owner_cache_status'] == 80 and
        state['_native_owner_cache_mount_status'] == -1 and state['_native_owner_cache_authorized'] == 0 and
        state['_native_owner_cache_root_recheck'] == 1 and
        state['_native_owner_cache_selected_device'] == state['_native_owner_cache_mounted_device'] == -1 and
        missing['native_virtio_integrity']['_native_virtio_verified_devices'] == 1, 'Absent authenticated SystemOS must actually refuse before startup flag publication')
dyld = (ROOT / '.cache/firmware/target-volumes/os-mount/usr/lib/dyld').read_bytes()
require(hashlib.sha256(dyld).hexdigest() == 'f8df3c58fae6e409db740df22c98aa699aee110b73523541a63f1bd5e23cf705', 'Require exact unchanged target dyld')
dyld_meta = np.macho(dyld)
def insn(pc):
    return struct.unpack_from('<I', dyld, np.backed_offset(dyld_meta['segments'], pc, 4, len(dyld)))[0]
word = insn(0x32ce4)
imm = (word >> 5) & 0x3fff
if imm & 0x2000: imm -= 0x4000
require(insn(0x32ce0) == 0x39416288 and word & 0x7f000000 == 0x37000000 and
        ((word >> 19) & 31) == 3 and word & 31 == 8 and 0x32ce4 + imm * 4 == 0x32e28, 'Actual target tests skipIgnition bit 3')
word = insn(0x32d18)
imm = word & 0x3ffffff
if imm & 0x2000000: imm -= 0x4000000
require(word >> 26 == 0x25 and 0x32d18 + imm * 4 == 0x34224, 'Original bit 3 skips actual ignite call')
print('PASS: owner-gated actual dyld/commpage bit 3; missing SystemOS refuses with all flags zero')
print('PASS: original cache preflight checks 53998 signed blocks, publishes 17 blobs and validates 68 native-4K pages')
print('Original asynchronous AMFI PMGR panic retained; full cache mapping, launchd main and hardware remain open')
