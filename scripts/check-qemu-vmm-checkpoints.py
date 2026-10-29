#!/usr/bin/env python3
"""Check actual original AMFI sysctl discovery of the offline QEMU identity."""
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


def tree(blob):
    def read(at):
        count, children = struct.unpack_from('<II', blob, at)
        at += 8
        properties = {}
        for _ in range(count):
            name, size = struct.unpack_from('<32sI', blob, at)
            at += 36
            name = name.split(b'\0')[0].decode()
            require(name not in properties and at + size <= len(blob), 'Bounded unique DT property')
            properties[name] = blob[at:at + size]
            at += (size + 3) & ~3
        nodes = {}
        for _ in range(children):
            child, at = read(at)
            name = child['properties']['name'].split(b'\0')[0].decode()
            require(name not in nodes, 'Unique child node')
            nodes[name] = child
        return dict(properties=properties, children=nodes), at
    result, end = read(0)
    require(end == len(blob), 'Consume exact DT')
    return result


folder = ROOT / 'build/darwinboot-owner-qemu-vmm-sysctl'
d = json.loads((folder / 'gdb-stop.json').read_text())
require(d['kernel_sha256'] == 'cef9ebddda8afc0e407cf933e0bfc97fabb6e754a0a2e3fcf740ef02188a07b3' and
        not d['bounded_timeout_interrupted'] and d['stop_symbol'] == 'original-component-address' and
        int(d['pc'], 16) == 0xfffffff004aae9d8 and int(d['x0'], 16) == 0 and
        struct.unpack_from('<I', bytes.fromhex(d['stack_bytes']), 12)[0] == 1,
        'Require actual successful original AMFI sysctl call and its real stack output 1')
blob = (folder / 'esp/EFI/UniXNU/Payloads/kernel.macho.adt').read_bytes()
require(d['offline_qemu_vmm_present_declared'] and hashlib.sha256(blob).hexdigest() == d['offline_device_tree_sha256'],
        'Pin actual QEMU DT input')
value = tree(blob)
require(value['properties']['model'] == b'qemu-entry-fixture\0' and
        value['properties']['compatible'] == b'linux,dummy-virt\0' and
        value['children']['defaults']['properties']['vmm-present'] == struct.pack('<I', 1),
        'Declare actual QEMU identity through native defaults ABI, no Apple identity')
require(d['original_crypto_initialized_observed'] and d['original_crypto_table_owner_observed'] and
        not d['ipados_userspace_boot_demonstrated'], 'Real original crypto, no full boot claim')
r = {k: int(v, 16) for k, v in d['system_registers'].items()}
require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and r['SCTLR_EL1'] & 1 and
        r['TTBR0_EL1'] and r['TTBR1_EL1'], 'Observe actual native 4K geometry')
binary = (ROOT / 'build/xnu-prelink/native-owner-dyld-startup-candidate.macho').read_bytes()
require(hashlib.sha256(binary).hexdigest() == d['kernel_sha256'], 'Exact original-component candidate')
meta = np.macho(binary)
def word(pc):
    return struct.unpack_from('<I', binary, np.backed_offset(meta['segments'], pc, 4, len(binary)))[0]
require(word(0xfffffff004aae9d8) == 0x35000120 and word(0xfffffff004aae9dc) == 0xb9400fe8 and
        word(0xfffffff004aae9e0) == 0x340000e8 and word(0xfffffff004aae9e8) == 0x52800029 and
        word(0xfffffff004aae9ec) == 0x3911c509 and word(0xfffffff004aaeaf8) == 0x3951c508 and
        word(0xfffffff004aaeafc) == 0x35000468,
        'Pin original successful-sysctl/output-dependent VM store and later PMGR branch')
baseline = ROOT / 'build/darwinboot-owner-cache-shared-region'
old = json.loads((baseline / 'gdb-stop.json').read_text())
old_tree = tree((baseline / 'esp/EFI/UniXNU/Payloads/kernel.macho.adt').read_bytes())
require(old['kernel_sha256'] == d['kernel_sha256'] and 'vmm-present' not in
        old_tree['children']['defaults']['properties'] and old['stop_symbol'] == '_panic' and
        'AMFI: No PMGR?' in old['argument_memory']['x0'], 'Preserve absent-VM-declaration control and genuine original PMGR refusal')
print('PASS: actual original AMFI kern.hv_vmm_present returns 0/output 1 under native-4K QEMU')
print('Offline environment only; the bare-metal sheng PMGR interface remains unresolved')
