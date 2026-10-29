#!/usr/bin/env python3
"""Require real refusal of one mutated original launchd code-page byte."""
import hashlib
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]
base = runpy.run_path(str(ROOT / 'scripts/check-original-launchd-main-checkpoints.py'))
require, positive = base['require'], base['main']
d = json.loads((ROOT / 'build/darwinboot-owner-hvf-launchd-main-code-fault/gdb-stop.json').read_text())
require(d['kernel_sha256'] == positive['kernel_sha256'] and
        d['trust_cache_bundle_sha256'] == positive['trust_cache_bundle_sha256'] and
        d['virtio_block_input'] == positive['virtio_block_input'] and
        d['virtio_extra_block_input'] == positive['virtio_extra_block_input'] and
        not d['bounded_timeout_interrupted'], 'Require the exact same kernel, original media and trust input')
fault = d['own_mapped_page_mutation']
require(fault and fault['file_page'] == 81920 and fault['byte_in_page'] == 3976 and
        fault['before'] == 255 and fault['after'] == 254 and
        fault['page_sha256_before'] == '32f1004a16014e6f56fc8b18dcb4e7bed2bb38353be71725b881cfc09d462621' and
        fault['code_directory_hash'] == '1d52c69747dffc4b1937d241bdbc9cee3b22df18' and
        fault['compiled_cdhash_field_offset'] == 88 and not fault['registers_or_validation_state_modified'],
        'Apply exactly one SHA/CDHash-qualified actual vnode-page input fault; no validation state changes')
require(d['original_launchd_page_fault_input'] == dict(
        file_sha256='8cec9a3c44a443b08e977ccc5d577850316ad428c575dc01f09b018dbd5b6a25',
        code_directory_hash='1d52c69747dffc4b1937d241bdbc9cee3b22df18', offset=85896,
        page_sha256=fault['page_sha256_before'], original_files_modified=False,
        signatures_or_trust_modified=False, actual_fault_applied=True), 'Preserve the unchanged supplied signed launchd input')
require(d['actual_signature_failures'] == dict(_cs_validate_page_bad_hash=1, _cs_validate_page_no_hash=0) and
        d['fatal_user_exit'] == dict(cs_status='CS_KILLED', prefix='initproc failed to start', namespace=3, code=2, description='none') and
        not d['original_launchd_main_executed'] and d['mapped_page_validation_entries'] == 1656 and
        d['mapped_page_validation_entries'] <= d['mapped_page_validation_entry_limit'] == 4096,
        'Genuine validation must kill the original process before main with a real bad hash')
require(d['owner_root_binding_audit']['boot_root_accepted'] and d['original_amfi_table_owner_observed'] and
        d['original_crypto_initialized_observed'] and d['native_virtio_globals']['_native_virtio_read_failures'] == 0 and
        d['native_virtio_integrity']['_native_virtio_integrity_failures'] == 0, 'Fault is after authenticated I/O, with real AMFI/crypto intact')
r = {k: int(v, 16) for k, v in d['system_registers'].items()}
require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and r['SCTLR_EL1'] & 1 and
        r['TTBR0_EL1'] and r['TTBR1_EL1'], 'Real refusal retains native hardware 4K')
print('PASS: one actual original launchd code byte is refused before LC_MAIN, bad hash 1/no hash 0 and CS_KILLED 3/2')
