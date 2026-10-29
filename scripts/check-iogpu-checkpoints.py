#!/usr/bin/env python3
"""Qualify actual original IOGPUFamily loading and native metaclass ABI evidence."""
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


source_hash = '257c6f553e0a30a577e8a53623fc742b46f337f55b912b5ff466c19b4c049828'
positive_hash = 'a66a3c60c82330cba7915a6dfd028cf6b2332e3919021f1fce9c0d0526498f99'
negative_hash = '043ec08b8ab0761412409fd2975e5a7d94ce8153ca1cd149bfe19f3053a72eb6'
directory = ROOT / 'build/xnu-prelink'
plans = {}
for stem, expected in (('native-owner-iogpu-candidate', positive_hash),
                       ('native-owner-iogpu-missing-candidate', negative_hash)):
    path = directory / (stem + '.macho')
    plan = json.loads(path.with_suffix('.json').read_text())
    require(plan['native_sha256'] == source_hash and plan['candidate_sha256'] == expected ==
            hashlib.sha256(path.read_bytes()).hexdigest() and plan['original_sha256'] ==
            'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7' and
            not plan['images_modified'] and not plan['source_inputs_modified'], 'Exact unchanged target and source/candidate identities')
    plans[expected] = plan
require(len(plans[positive_hash]['components']) == 29 and len(plans[negative_hash]['components']) == 28 and
        set(plans[positive_hash]['components']) - set(plans[negative_hash]['components']) == {'com.apple.iokit.IOGPUFamily'},
        'Actual component present/absent closure')
image = (directory / 'native-owner-iogpu-candidate.macho').read_bytes()
segments = macho(image)['segments']


def read(va, size):
    at = backed_offset(segments, va, size, len(image))
    return image[at:at + size]


def report(label, expected=positive_hash):
    d = json.loads((ROOT / ('build/darwinboot-owner-hvf-iogpu-' + label) / 'gdb-stop.json').read_text())
    r = {name: int(value, 16) for name, value in d['system_registers'].items()}
    require(d['kernel_sha256'] == expected and d['qemu_accelerator'] == 'hvf' and not d['bounded_timeout_interrupted'] and
            d['native_4k_mmu_observed'] and r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'] and
            d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'] and
            not d['sheng_hardware_tested'], 'Actual bounded native-4K XNU and original crypto')
    return d


loaded, missing = report('load'), report('missing', negative_hash)
require(loaded['stop_symbol'] == missing['stop_symbol'] == '_native_iogpu_probe_checkpoint' and
        loaded['native_iogpu_load_status'] == 0 and missing['native_iogpu_load_status'] == -603946998,
        'Real original component load and genuine component-absent refusal')
component = loaded['native_iogpu_component']
require(component['actual_start_observed'] and component['original_entry_bytes_match'] and
        component['start'] == '0xfffffff004bde714' and component['original_start'] == '0xfffffff005bde714' and
        any(e['pc'] == component['start'] and e['symbol'] == 'com.apple.iokit.IOGPUFamily:kmod_start' for e in loaded['trace_events']),
        'Actual original IOGPU kmod start with unchanged entry instructions')

symbols = subprocess.check_output(['xcrun', 'nm', '-U', directory / 'native-owner-iogpu-candidate.macho'], text=True)


def symbol(name):
    match = re.search(r'^([0-9a-f]+)\s+\S\s+' + re.escape(name) + '$', symbols, re.M)
    require(match, 'Qualified actual native symbol: ' + name)
    return int(match[1], 16)


def owner(va):
    return any(e['module'] == 'com.apple.iokit.IOGPUFamily' and e['segment'] == '__DATA' and
               e['va'] <= va < e['va'] + e['size'] for e in plans[positive_hash]['extents'])


records = {}
for label, name, size, parent in (
        ('gpu', 'IOGPU', 0x2e0, 0xfffffff006aeb688),
        ('device', 'IOGPUDevice', 0x100, 0xfffffff006aeb278),
        ('userclient', 'IOGPUDeviceUserClient', 0x130, symbol('__ZN12IOUserClient10gMetaClassE'))):
    d = report(label + '-class')
    args = [int(value, 16) for value in d['function_entry_arguments']]
    raw = bytes.fromhex(d['entry_regions']['0:0:80']['bytes'])
    require(d['function_return_stack_matched'] and d['entry_kernel_bytes_match']['bytes'] == (name + '\0').encode().hex() and
            args[2:4] == [parent, size] and struct.unpack_from('<Q', raw, 16)[0] == parent and
            struct.unpack_from('<Q', raw, 24)[0] == args[1] and struct.unpack_from('<I', raw, 32)[0] == size and owner(args[0]),
            'Actual metaclass constructor, original class storage/name, parent and qualified fields')
    records[name] = dict(metaclass=hex(args[0]), parent=hex(parent), instance_bytes=size,
                         constructor_observed=True, runtime_instance_created=False)
    if label != 'userclient':
        # These original parents are constructed within the same module before
        # postModLoad converts class-name C strings to registered OSSymbols.
        parent_name, parent_size, grandparent = (
            ('IOAcceleratorES', 0x88, symbol('__ZN9IOService10gMetaClassE')) if label == 'gpu' else
            ('IOGPUObject', 0x10, symbol('__ZN8OSObject10gMetaClassE')))
        raw = bytes.fromhex(d['entry_regions']['2:0:80']['bytes'])
        name_pointer, = struct.unpack_from('<Q', raw, 24)
        require(owner(parent) and read(name_pointer, len(parent_name) + 1) == (parent_name + '\0').encode() and
                struct.unpack_from('<Q', raw, 16)[0] == grandparent and struct.unpack_from('<I', raw, 32)[0] == parent_size,
                'Actual initialized parent metadata, not an invented inheritance relationship')
        records[parent_name] = dict(metaclass=hex(parent), parent=hex(grandparent), instance_bytes=parent_size,
                                    constructor_observed=False, initialized_parent_observed=True, runtime_instance_created=False)
for label, status in (('launchd-main', 0), ('default-off', -1)):
    d = report(label)
    require(d['native_iogpu_load_status'] == status and d['original_amfi_table_owner_observed'] and
            d['original_launchd_main_executed'] and d['followed_main_entry']['first_instruction_completed'] and
            int(d['pstate'], 16) & 31 == 0 and
            d['direct_user_commpage_shifts'] == {'fffff4025:1': 12, 'fffff4037:1': 12} and
            d['owner_root_binding_audit']['boot_root_accepted'] and
            d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80 and
            d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
            d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0,
            'Original EL0 launchd, native user 4K, owner-root binding and genuine signatures with enabled/default-off load')
(ROOT / 'build/gpu-analysis/iogpu-class-abi.json').write_text(json.dumps(dict(classes=records,
    gpu_instance_created=False, metal_device_created=False, adreno_execution_qualified=False), indent=2) + '\n')
print('PASS: actual original IOGPUFamily start/load and missing-component refusal; three constructors and two parent metadata records')
print('PASS: original launchd with load enabled/default-off; no GPU instance, Metal device or Adreno execution claim')
