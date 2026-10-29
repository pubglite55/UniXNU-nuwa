#!/usr/bin/env python3
"""Check bounded real original class allocation and invalid-request evidence."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source_hash = 'efc9d01ee7827379075c7163a73abc7d737271ecd5910856dc29de4a3e778e5f'
candidate_hash = '6fe38be5ed8d2919dddabb270633acb6a628c965be1f58d3e430190687e0d7c1'
candidate = ROOT / 'build/xnu-prelink/native-owner-mobile-client-candidate.macho'
plan = json.loads(candidate.with_suffix('.json').read_text())


def require(value, message):
    if not value:
        raise SystemExit(message)


require(hashlib.sha256(candidate.read_bytes()).hexdigest() == plan['candidate_sha256'] == candidate_hash and
        plan['native_sha256'] == source_hash and plan['original_sha256'] ==
        'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7', 'Exact candidate/source/original identities')
reports = {}
for label in ('client', 'client-launchd-main', 'client-default-off'):
    d = json.loads((ROOT / ('build/darwinboot-owner-hvf-mobile-graphics-' + label) / 'gdb-stop.json').read_text())
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(d['kernel_sha256'] == candidate_hash and d['qemu_accelerator'] == 'hvf' and
            not d['bounded_timeout_interrupted'] and not d['sheng_hardware_tested'] and
            d['native_4k_mmu_observed'] and r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'] and
            d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'] and
            d['native_mobile_graphics_load_status'] == 0 and
            d['native_mobile_graphics_component']['original_entry_bytes_match'], 'Bounded actual native-4K kernel and genuine original family loading')
    client = d['native_mobile_graphics_client']
    if label == 'client-default-off':
        require(client == dict(abstract_null_mask=0, client_object=0, client_vptr=0, client_meta=0,
                               client_size=0, client_init=-1, client_released=0, selector_results=[0xffffffff] * 3),
                'The independent client instrument remains default-off')
    else:
        require(client['abstract_null_mask'] == 7 and client['client_object'] >= 0xfffffff000000000 and
                client['client_vptr'] == 0xfffffff005f34dd0 and client['client_meta'] == 0xfffffff006b313b0 and
                client['client_size'] == 0x538 and client['client_init'] == client['client_released'] == 1 and
                client['selector_results'] == [0xe0000001] * 3,
                'Actual original abstract factory refusals, client construction/init/release and three unsigned-range refusals')
    if label != 'client':
        require(d['original_launchd_main_executed'] and d['followed_main_entry']['first_instruction_completed'] and
                int(d['pstate'], 16) & 31 == 0 and
                d['direct_user_commpage_shifts'] == {'fffff4025:1': 12, 'fffff4037:1': 12} and
                d['owner_root_binding_audit']['boot_root_accepted'] and d['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80 and
                d['owner_boot_manifest']['status'] == 0 and d['original_amfi_table_owner_observed'] and
                d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=0, _cs_validate_page_no_hash=0) and
                d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0,
                'Original launchd survives enabled/default-off client controls with intact trust, signatures and user 4K')
    reports[label] = d

factories = [('IOMobileFramebuffer', 0xfffffff00577b420, 0xfffffff006b313d8),
             ('IOMobileFramebufferService', 0xfffffff00577b620, 0xfffffff006b31400),
             ('IOMobileFramebufferLegacy', 0xfffffff0057866d4, 0xfffffff006b35940)]
for name, pc, meta in factories:
    require(any(e['symbol'] == name + '::MetaClass::alloc' and int(e['pc'], 16) == pc and int(e['x0'], 16) == meta
                for e in reports['client']['trace_events']), 'Actual original abstract factory must run: ' + name)
require(reports['client']['stop_symbol'] == '_native_mobile_graphics_client_checkpoint' and
        any(e['symbol'] == 'IOMobileFramebufferUserClient::externalMethod' and e['x1'] == '0x5a' and
            int(e['x0'], 16) == reports['client-launchd-main']['native_mobile_graphics_client']['client_object']
            for e in reports['client-launchd-main']['trace_events']), 'Actual original request entry on the allocated client')
print('PASS: all three original abstract factories actually run and return null; concrete original client allocates, initializes and releases')
print('PASS: selectors 90/0x80000000/0xffffffff really refuse; original launchd main, native 4K and trust survive enabled/default-off controls')
