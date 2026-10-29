#!/usr/bin/env python3
"""Qualify original display-family initialization and bounded class ABI evidence."""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import backed_offset, macho


def require(value, message):
    if not value:
        raise SystemExit(message)


source_hash = '8b78575592b37bfc8a180fb4a029383287b3a9a032841dfc4efcb5cdeb656cdb'
positive_hash = 'aded28d3c61dafaf7b8a7c96b14427a798e9e95470ae6f287bcd038c07626798'
negative_hash = 'e3748f2c9e4f0d06d5ed925d278662c207cf14efb0a2d8a70c28f389848b81f1'
directory = ROOT / 'build/xnu-prelink'
images = {}
for stem, expected in (('native-owner-mobile-graphics-candidate', positive_hash),
                       ('native-owner-mobile-graphics-missing-candidate', negative_hash)):
    path = directory / (stem + '.macho')
    plan = json.loads(path.with_suffix('.json').read_text())
    require(plan['native_sha256'] == source_hash and plan['candidate_sha256'] == expected ==
            hashlib.sha256(path.read_bytes()).hexdigest(), 'Exact source/candidate identities')
    images[expected] = plan
require(len(images[positive_hash]['components']) == 28 and len(images[negative_hash]['components']) == 18 and
        'com.apple.iokit.IOMobileGraphicsFamily' not in images[negative_hash]['components'], 'Actual component-present/absent candidates')
image = (directory / 'native-owner-mobile-graphics-candidate.macho').read_bytes()
segments = macho(image)['segments']


def read(va, size):
    at = backed_offset(segments, va, size, len(image))
    return image[at:at + size]


def report(label, expected=positive_hash):
    d = json.loads((ROOT / ('build/darwinboot-owner-hvf-mobile-graphics-' + label) / 'gdb-stop.json').read_text())
    r = {name: int(value, 16) for name, value in d['system_registers'].items()}
    require(d['kernel_sha256'] == expected and d['qemu_accelerator'] == 'hvf' and not d['bounded_timeout_interrupted'] and
            d['native_4k_mmu_observed'] and r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'] and
            d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'] and
            not d['sheng_hardware_tested'], 'Bounded actual native-4K kernel and original crypto')
    return d


loaded, missing = report('load'), report('missing', negative_hash)
require(loaded['stop_symbol'] == missing['stop_symbol'] == '_native_mobile_graphics_probe_checkpoint' and
        loaded['native_mobile_graphics_load_status'] == 0 and missing['native_mobile_graphics_load_status'] == -603946998,
        'Real load returns zero; missing prelinked component returns kOSKextReturnDisabled (0xdc00800a)')
component = loaded['native_mobile_graphics_component']
require(component['actual_start_observed'] and component['original_entry_bytes_match'] and
        component['start'] == '0xfffffff0057a2654' and component['original_start'] == '0xfffffff0067a2654' and
        any(e['pc'] == component['start'] and e['symbol'] == 'com.apple.iokit.IOMobileGraphicsFamily:kmod_start' for e in loaded['trace_events']),
        'Actual original kmod start and original instruction bytes')
print('PASS: actual original IOMobileGraphicsFamily starts and loads; component-absent control genuinely refuses')

symbols = subprocess.check_output(['xcrun', 'nm', '-U', directory / 'native-owner-mobile-graphics-candidate.macho'], text=True)
def symbol(name):
    return int(re.search(r'^([0-9a-f]+)\s+\S\s+' + re.escape(name) + '$', symbols, re.M)[1], 16)

records = {}
for label, name, size, parent in (
        ('framebuffer', 'IOMobileFramebuffer', 0x90, symbol('__ZN9IOService10gMetaClassE')),
        ('userclient', 'IOMobileFramebufferUserClient', 0x538, symbol('__ZN12IOUserClient10gMetaClassE')),
        ('service', 'IOMobileFramebufferService', 0x90, 0xfffffff006b313d8),
        ('legacy', 'IOMobileFramebufferLegacy', 0x18a0, 0xfffffff006b31400)):
    d = report(label + '-class')
    args = [int(value, 16) for value in d['function_entry_arguments']]
    raw = bytes.fromhex(d['entry_regions']['0:0:80']['bytes'])
    require(d['function_return_stack_matched'] and d['entry_kernel_bytes_match']['bytes'] == (name + '\0').encode().hex() and
            args[2:4] == [parent, size] and struct.unpack_from('<Q', raw, 16)[0] == parent and
            struct.unpack_from('<Q', raw, 24)[0] == args[1] and struct.unpack_from('<I', raw, 32)[0] == size,
            'Actual original metaclass constructor, class name, parent and compiler-qualified fields')
    require(any(e['module'] == 'com.apple.iokit.IOMobileGraphicsFamily' and e['segment'] == '__DATA' and
                e['va'] <= args[0] < e['va'] + e['size'] for e in images[positive_hash]['extents']), 'Original metaclass storage ownership')
    base_vptr, = struct.unpack_from('<Q', raw)
    require([i for i in range(64) if struct.unpack('<Q', read(base_vptr + i * 8, 8))[0] == symbol('___cxa_pure_virtual')] == [13],
            'Actual native metaclass alloc virtual slot')
    pc = int(d['function_return_target'], 16) - 0x34
    adrp, add, adjust = struct.unpack('<3I', read(pc, 12))
    require(adrp & 0x9f00001f == 0x90000008 and add & 0xffc003ff == 0x91000108 and adjust == 0x91004108,
            'Original constructor must supply the qualified derived metaclass vptr')
    immediate = ((adrp >> 5) & 0x7ffff) << 2 | ((adrp >> 29) & 3)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    vptr = (pc & ~4095) + (immediate << 12) + ((add >> 10) & 4095) + 16
    alloc, = struct.unpack('<Q', read(vptr + 13 * 8, 8))
    abstract = label != 'userclient'
    if abstract:
        require(read(alloc, 20) == bytes.fromhex('ff4300d1e00700f9000080d2ff430091c0035fd6'), 'Original abstract factory returns null')
    else:
        require(struct.unpack('<I', read(alloc + 16, 4))[0] == (0xd2800000 | (size << 5)), 'Original concrete factory supplies the actual object size')
    records[name] = dict(metaclass=hex(args[0]), parent=hex(parent), instance_bytes=size,
                         vptr=hex(vptr), alloc=hex(alloc), static_abstract_factory=abstract, runtime_instance_created=False)
print('PASS: four original metaclass constructors; three abstract framebuffer factories and concrete userclient factory identified statically')

for label, status in (('launchd-main', 0), ('default-off', -1)):
    d = report(label)
    require(d['native_mobile_graphics_load_status'] == status and d['original_amfi_table_owner_observed'] and
            d['original_launchd_main_executed'] and
            d['followed_main_entry']['first_instruction_completed'] and int(d['pstate'], 16) & 31 == 0 and
            d['direct_user_commpage_shifts'] == {'fffff4025:1': 12, 'fffff4037:1': 12} and
            d['owner_root_binding_audit']['boot_root_accepted'] and d['owner_boot_manifest']['status'] == 0 and
            d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
            d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0,
            'Real original launchd and security survive; explicit load instrument remains default-off')
(ROOT / 'build/display-analysis/mobile-graphics-class-abi.json').write_text(json.dumps(records, indent=2) + '\n')
print('PASS: original launchd main with load enabled/default-off, native hardware/user 4K, intact owner roots and signatures; no display service claim')
