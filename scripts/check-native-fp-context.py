#!/usr/bin/env python3
"""Verify actual full SIMD preservation on the original-root native-4K instrument."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'build/native-fp-context'
def require(value,reason):
    if not value:raise SystemExit(reason)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
build=json.loads((OUT/'build-report.json').read_text())
manifest=json.loads((OUT/'test-inputs.json').read_text())
data=json.loads((OUT/'data-report.json').read_text())
path=ROOT/'build/darwinboot-owner-hvf-fp-context-system-final/gdb-stop.json';d=json.loads(path.read_text())
plan=json.loads((ROOT/'build/xnu-prelink/native-owner-legacy-display-info-candidate.json').read_text())
require(sha(OUT/'air-native')==sha(OUT/'launchd.macho')==build['process_sha256']==data['process_sha256']==d['native_user_image_sha256'] and
        sha(OUT/'test-inputs.json')==build['manifest_sha256']==data['manifest_sha256'] and
        sha(ROOT/'scripts/qemu-entry/native-fp-context.inc')==manifest['source_sha256'],
        'Exact own source, signed process and staged instrument manifest')
require(sha(OUT/'compiler-data-32.cdr')==data['sha256']==d['scratch_data']['actual_seed_sha256'] and
        sha(OUT/'offline-trust.bundle')==build['trust_bundle_sha256']==d['trust_cache_bundle_sha256'],
        'Exact real mutable Data input and trust bundle')
original=(ROOT/'build/original-static-system-trust/original-static-system.bundle').read_bytes()
trust=(OUT/'offline-trust.bundle').read_bytes()
require(struct.unpack_from('<I',original)[0]==2 and struct.unpack_from('<I',trust)[0]==3,'Original and own trust bundle shapes')
old=struct.unpack_from('<2I',original,4);new=struct.unpack_from('<3I',trust,4)
require([original[old[0]:old[1]],original[old[1]:]]==[trust[new[1]:new[2]],trust[new[2]:]],
        'Both original trust modules unchanged; only the explicit own instrument is added')
subprocess.run(['codesign','--verify','--strict',OUT/'launchd.macho'],check=True,capture_output=True)
detail=subprocess.run(['codesign','--display','--verbose=4',OUT/'launchd.macho'],check=True,capture_output=True,text=True).stderr
require('Page size=4096' in detail and build['code_signature_page_bytes']==4096,'Actual own CodeDirectory granule is 4K')
require(d['kernel_sha256']==plan['candidate_sha256'] and not d['bounded_timeout_interrupted'] and
        d['native_user_el0_observed'] and d['native_user_4k_abi_observed'] and d['native_4k_mmu_observed'],
        'Real bounded EL0 instrument, active hardware translation and page-size ABI on the exact kernel')
memory=d['native_user_memory'];values=struct.unpack('<10Q',bytes.fromhex(memory['_fp_context_results']))
status,iterations,trap_status,phase,index,wanted,actual,start,end,frequency=values
expected=b''.join(struct.pack('<2Q',0x3ff0000000000000+i,0x4000000000000000+i) for i in range(32))
require(status==0 and iterations==32 and not any((trap_status,phase,index,wanted,actual)) and
        bytes.fromhex(memory['_fp_context_expected'])==bytes.fromhex(memory['_fp_context_actual'])==expected,
        'All 128 bits of all 32 SIMD registers survive 32 BSD syscalls and 32 successful blocking Mach thread switches')
require(end>start and frequency==int(d['system_registers']['CNTFRQ_EL0'],16) and 0.025<=(end-start)/frequency<5,
        'Actual architectural counter confirms bounded blocking-time execution')
require(d['original_amfi_table_owner_observed'] and d['owner_root_binding_audit']['boot_root_accepted'] and
        d['owner_root_binding_audit']['_native_owner_root_apple_autherr']==80 and
        d['actual_signature_failures']==dict(_cs_validate_page_bad_hash=0,_cs_validate_page_no_hash=0),
        'Original AMFI, original Apple rejection, independent original-root acceptance and no code-sign hash failures')
(OUT/'checkpoint.json').write_text(json.dumps(dict(checkpoint_sha256=sha(path),candidate_sha256=plan['candidate_sha256'],
    process_sha256=build['process_sha256'],simd_registers=32,bits_per_register=128,iterations=iterations,
    blocking_thread_switches=32,elapsed_seconds=(end-start)/frequency,native_cpu_4k=True,
    original_root=True,mockfs_boot=False,original_desktop=False,adreno_execution=False,hardware_tested=False),indent=2)+'\n')
print('PASS: all 32 full SIMD registers survive real syscalls and 32 blocking thread switches; native 4K/original root/AMFI intact')
print('CPU context instrument only; it does not qualify system UI or Adreno execution')
