#!/usr/bin/env python3
"""Verify actual defaults enumeration and the unchanged Image4 service wait."""
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
import native_prelink as np

build = ROOT / 'build'
plan = json.loads((build / 'xnu-prelink/native-defaults-candidate.json').read_text())
audit = json.loads((build / 'image4-ignition/audit.json').read_text())
kernel = (build / 'xnu-prelink/native-defaults-candidate.macho').read_bytes()
native = np.macho(kernel)


def require(value, message):
    if not value:
        raise SystemExit('FAIL: ' + message)


def read_report(name):
    d = json.loads((build / name / 'gdb-stop.json').read_text())
    require(d['kernel_sha256'] == plan['candidate_sha256'], 'same exact native/original-component candidate')
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'], 'actual native 4K hardware')
    return d


positive = read_report('darwinboot-defaults-configure-strict')
negative = read_report('darwinboot-defaults-unmatched-strict')
require(positive['original_crypto_initialized_observed'] and negative['original_crypto_initialized_observed'],
        'genuine original crypto before platform matching')
require(not positive['bounded_timeout_interrupted'] and int(positive['x0'], 16) == 1 and
        positive['pc'] == positive['function_return_target'], 'actual configure returned true')
g = positive['armvirt_globals']
require(all(g[n] == 1 for n in ('_armvirt_platform_configured', '_armvirt_platform_cpu_count',
        '_armvirt_platform_bus_count', '_armvirt_platform_defaults_count')), 'actual required DT nubs')
require(g['_armvirt_platform_child_count'] == 5, 'actual child count, not an assumed device count')
require(not negative['bounded_timeout_interrupted'] and not any(negative['armvirt_globals'].values()) and
        'Unable to find driver for this platform' in negative['argument_memory']['x0'], 'original platform refusal')

service = read_report('darwinboot-target-dyld-defaults-services')
require(service['kernel_observations']['_armvirt_platform_defaults_count'] == 1 and
        service['kernel_observations']['_armcpu_timer_interrupts'] > 0, 'enumerated node and genuine interrupts')
queries = [q for q in service['cstring_events'] if q['value'] == 'IOAESAccelerator']
require(len(queries) == 1 and not service['cstring_log_exhausted'], 'bounded actual AES service request')
query = queries[0]
require(any(e['module'] == 'com.apple.security.AppleImage4' and e['segment'] == '__TEXT_EXEC' and
            e['va'] <= int(query['caller'], 16) < e['va'] + e['size'] for e in plan['extents']),
        'actual request caller is the original Image4 module')
at = np.backed_offset(native['segments'], int(query['argument'], 16), 17, len(kernel))
require(kernel[at:at + 17] == b'IOAESAccelerator\0', 'original request string')
last = service['syscall_events'][-1]
require(last['number'] == 202 and struct.unpack('<4I', bytes.fromhex(last['sysctl_mib_bytes'])) ==
        (101, 100, 118, 100) and service['bounded_timeout_interrupted'], 'measured ignition wait, not prepare success')

wait = read_report('darwinboot-image4-aes-wait-entry')
exports = np.exports(kernel, native)
require('__ZN9IOService22waitForMatchingServiceEP12OSDictionaryy' in exports[int(wait['pc'], 16)],
        'actual source waitForMatchingService entry')
require(not wait['bounded_timeout_interrupted'] and int(wait['x1'], 16) == (1 << 64) - 1 and
        int(wait['x30'], 16) == int(query['caller'], 16) + 12, 'original Image4 requested unbounded service wait')
require(any(int(t['pc'], 16) == int(query['caller'], 16) - 4 for t in wait['trace_events']),
        'same original serviceMatching call precedes the actual wait')
require(audit['candidate_sha256'] == plan['candidate_sha256'] and audit['compiled_oid_offsets'] ==
        dict(oid_name=40, oid_handler=48) and not audit['code_or_security_result_modified'], 'qualified original handler analysis')
require(any('_lck_mtx_gate_wait' in c['names'] for c in audit['kernel_calls']), 'real source gate-wait binding')

abi = read_report('darwinboot-target-dyld-defaults-mach-init')
require(abi['original_dyld_mach_init_returned'] and abi['original_dyld_native_4k_abi_observed'] and
        abi['original_dyld_page_abi'] == dict(_vm_page_size=4096, _vm_page_mask=4095,
        _vm_page_shift=12, _vm_kernel_page_shift=12), 'current platform still qualifies genuine target dyld page ABI')
require(abi['kernel_observations']['_armvirt_platform_defaults_count'] == 1 and
        not abi['bounded_timeout_interrupted'], 'actual defaults/ABI regression checkpoint')

result = dict(candidate_sha256=plan['candidate_sha256'], checkpoints=5, defaults_nub_published=True,
              unmatched_platform_refused=True, original_image4_aes_request_observed=True,
              actual_wait_timeout=(1 << 64) - 1, original_ignition_handler_unchanged=True,
              original_target_dyld_4k_abi_retained=True,
              aes_provider_initialized=False, ignition_blob_published=False,
              dyld_prepare_reached=False, functional_ipados_booted=False, hardware_tested=False)
(build / 'image4-ignition/service-checkpoints.json').write_text(json.dumps(result, indent=2) + '\n')
print('PASS: actual defaults enumeration, refusal control and original Image4 request/wait for IOAESAccelerator')
print('AES service and ignition publication remain missing; no successful startup is inferred from a timeout')
