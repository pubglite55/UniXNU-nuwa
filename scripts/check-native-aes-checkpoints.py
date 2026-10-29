#!/usr/bin/env python3
"""Verify genuine CBC/refusal tests and original dyld prepare/cache observations."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
import native_prelink as np
build = ROOT / 'build'


def require(value, message):
    if not value:
        raise SystemExit('FAIL: ' + message)


def plan(name):
    path = build / 'xnu-prelink' / (name + '.macho')
    data = path.read_bytes()
    result = json.loads(path.with_suffix('.json').read_text())
    require(hashlib.sha256(data).hexdigest() == result['candidate_sha256'], 'candidate identity')
    require(not result['images_modified'] and not result['source_inputs_modified'] and
            result['original_sha256'] == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7',
            'unchanged original input provenance')
    parsed = np.macho(data)
    for extent in result['extents']:
        if extent['segment'] == '__TEXT_EXEC':
            at = np.backed_offset(parsed['segments'], extent['va'], extent['size'], len(data))
            require(hashlib.sha256(data[at:at + extent['size']]).hexdigest() ==
                    result['original_executable_sha256'][extent['module']], 'unchanged actual original executable extent')
    return result


positive = plan('native-aes-api-candidate')
negative = plan('native-aes-kat-negative-candidate')
require(positive['original_executable_sha256'] == negative['original_executable_sha256'],
        'all genuine original component code retained in both controls')
own = (ROOT / 'drivers/SoftwareAES/NativeAES.cpp').read_text()
control = (build / 'software-aes-kat-negative/NativeAES.cpp').read_text()
require(own.count('0x76,0x49,0xab,0xac') == 1 and
        control == own.replace('0x76,0x49,0xab,0xac', '0x77,0x49,0xab,0xac'),
        'negative control changes only one own known-answer byte')
bindings = json.loads((build / 'software-aes/bindings.json').read_text())
require(bindings['compiled_subclass_slots_checked'] == 181 and
        not bindings['original_instructions_modified'], 'compiled ordinary iOS subclass dispatch')
require(hashlib.sha256((build / 'software-aes/NativeAES.o').read_bytes()).hexdigest() ==
        bindings['compiled_subclass_sha256'], 'qualified subclass object identity')


def report(name, candidate):
    d = json.loads((build / name / 'gdb-stop.json').read_text())
    require(d['kernel_sha256'] == candidate['candidate_sha256'] and not d['bounded_timeout_interrupted'],
            'actual bounded checkpoint with exact candidate')
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'], 'actual native hardware 4K')
    return d


started = report('darwinboot-native-aes-api-start-stack', positive)
refused = report('darwinboot-native-aes-kat-refusal-stack', negative)
for d, expected in ((started, 1), (refused, 0)):
    require(d['function_return_stack_matched'] and d['sp'] == d['function_entry_stack'] and
            d['pc'] == d['function_return_target'] and int(d['x0'], 16) == expected,
            'actual original-thread start return, not another driver at the shared caller')
    require(d['original_crypto_initialized_observed'], 'genuine original crypto registration')
require(started['native_aes_globals'] == dict(_native_aes_kat_status=1, _native_aes_interface_status=1,
        _native_aes_registered=1, _native_aes_completed=3, _native_aes_unsupported_key=1),
        'AES-128/192/256 answers, descriptor/raw/in-place operations, bounds and hardware-key refusal')
require(refused['native_aes_globals']['_native_aes_kat_status'] == 2 and
        refused['native_aes_globals']['_native_aes_registered'] == 0,
        'wrong own known answer genuinely prevents service publication')

fixture = json.loads((build / 'target-dyld-fixture/inputs.json').read_text())
dyld = (build / 'target-dyld-fixture/dyld').read_bytes()
require(hashlib.sha256(dyld).hexdigest() == 'f8df3c58fae6e409db740df22c98aa699aee110b73523541a63f1bd5e23cf705',
        'unchanged supplied ordinary ARM64 dyld')
prepared = report('darwinboot-target-dyld-aes-api-prepare', positive)
cache = report('darwinboot-target-dyld-cache-loader', positive)
for d in (prepared, cache):
    require(d['target_inputs']['root_sha256'] == fixture['root_sha256'] and
            d['target_inputs']['trust_bundle_sha256'] == fixture['trust_bundle_sha256'], 'same original target root/trust input')
    require(d['original_dyld_page_abi'] == dict(_vm_page_size=4096, _vm_page_mask=4095,
            _vm_page_shift=12, _vm_kernel_page_shift=12), 'original dyld native page ABI')
    g = d['kernel_observations']
    require(g['_native_aes_kat_status'] == g['_native_aes_interface_status'] == g['_native_aes_registered'] == 1,
            'genuine tested AES service available at original user checkpoint')
    require(g['_cs_validate_page_bad_hash'] == g['_cs_validate_page_no_hash'] == 0, 'genuine code-page integrity')
    checkpoint = d['followed_user_entry']['checkpoint']
    offset = int(checkpoint['pc'], 16) - int(d['original_dyld_slide'], 16)
    require(checkpoint['observed'] and int(checkpoint['pstate'], 16) & 15 == 0 and
            checkpoint['bytes'] == dyld[offset:offset + 16].hex(), 'byte-matched actual original EL0 checkpoint')
    require(not d['target_launchd_main_executed'] and not d['functional_ipados_boot_demonstrated'] and
            not d['sheng_hardware_tested'], 'component checkpoint scope')
require(int(prepared['followed_user_entry']['checkpoint']['pc'], 16) - int(prepared['original_dyld_slide'], 16) ==
        fixture['dyld_symbols']['__ZN5dyld4L7prepareERNS_4APIsEPKN5dyld313MachOAnalyzerE'] + 4,
        'actual original dyld4::prepare entry')
returned = cache['followed_user_entry']['function_return']
require(cache['original_dyld_cache_loader_returned'] and returned['observed'] and
        int(returned['pstate'], 16) & 15 == 0 and int(returned['x0'], 16) == 0,
        'actual original cache loader returned false, not a mapped-cache success')
words = struct.unpack('<8Q', bytes.fromhex(cache['followed_user_entry']['checkpoint_argument_memory']['1:40']['bytes']))
require(words[0:2] == (0, 0), 'no actual cache mapping in the loader result')
offset = words[2] - int(cache['original_dyld_slide'], 16)
require(0 <= offset < len(dyld) and dyld[offset:offset + 256].split(b'\0', 1)[0] ==
        b'shared cache file open() failed', 'actual error pointer identifies the original input message')
require(any(e['number'] == 5 and e.get('path') == '/System/Library/Caches/com.apple.dyld/'
            for e in cache['syscall_events']), 'actual attempted shared-cache directory open')
result = dict(candidate_sha256=positive['candidate_sha256'], negative_candidate_sha256=negative['candidate_sha256'],
              checked_qemu_reports=4, actual_thread_returns_verified=True, genuine_crypto_known_answers_passed=True,
              wrong_known_answer_prevents_registration=True, original_component_code_unchanged=True,
              original_dyld_prepare_entered=True, original_cache_loader_returned=True,
              original_cache_loader_success=False, original_cache_load_address=0,
              original_error_message_pointer_target='shared cache file open() failed',
              native_4k=True, target_launchd_main_executed=False, functional_ipados_booted=False, hardware_tested=False)
(build / 'software-aes/checkpoints.json').write_text(json.dumps(result, indent=2) + '\n')
print('PASS: genuine AES answers/interfaces, wrong-answer service refusal and original native-4K dyld prepare/cache loader')
print('Cache directory is missing in the two-file root; no cache mapping, launchd main, iPadOS UI or hardware boot is claimed')
