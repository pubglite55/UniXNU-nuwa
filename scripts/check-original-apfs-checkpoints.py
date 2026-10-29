#!/usr/bin/env python3
"""Verify original APFS kext startup and real native-4K VFS registration."""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
import native_prelink as np
build = ROOT / 'build'


def require(value, message):
    if not value:
        raise SystemExit('FAIL: ' + message)


def load_plan(name):
    path = build / 'xnu-prelink' / (name + '.macho')
    data = path.read_bytes()
    plan = json.loads(path.with_suffix('.json').read_text())
    require(hashlib.sha256(data).hexdigest() == plan['candidate_sha256'], 'actual candidate identity')
    require(not plan['source_inputs_modified'] and not plan['images_modified'] and
            plan['original_sha256'] == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7',
            'original ordinary ARM64 target provenance')
    image = np.macho(data)
    for extent in plan['extents']:
        if extent['segment'] == '__TEXT_EXEC':
            at = np.backed_offset(image['segments'], extent['va'], extent['size'], len(data))
            require(hashlib.sha256(data[at:at + extent['size']]).hexdigest() ==
                    plan['original_executable_sha256'][extent['module']], 'genuine original executable code retained')
    return data, image, plan


data, image, positive = load_plan('native-apfs-load-positive')
_, _, negative = load_plan('native-apfs-load-missing')
require(positive['native_sha256'] == negative['native_sha256'], 'same native source kernel')
require('com.apple.filesystems.apfs' in positive['components'] and
        'com.apple.filesystems.apfs' not in negative['components'], 'real component presence/refusal control')


def report(name, plan):
    d = json.loads((build / name / 'gdb-stop.json').read_text())
    require(d['kernel_sha256'] == plan['candidate_sha256'] and not d['bounded_timeout_interrupted'],
            'bounded exact-candidate observation')
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'], 'active native 4K hardware roots')
    return d


loaded = report('darwinboot-apfs-load-start-trace', positive)
missing = report('darwinboot-apfs-load-missing', negative)
registered = report('darwinboot-apfs-vfs-register', positive)
require(loaded['native_apfs_globals']['_native_apfs_load_status'] == 0 and
        loaded['original_crypto_initialized_observed'], 'genuine kext load API returned success after original crypto')
start = positive['module_entrypoints']['com.apple.filesystems.apfs']['start_va']
require(any(int(e['pc'], 16) == start and e.get('symbol') == 'com.apple.filesystems.apfs:kmod_start'
            for e in loaded['trace_events']), 'actual original APFS kmod entry executed')
require(missing['native_apfs_globals']['_native_apfs_load_status'] != 0 and
        missing['native_apfs_globals']['_native_apfs_registered'] == 0 and
        missing['native_apfs_globals']['_native_apfs_vfsops'] == 0, 'missing original module is not reported as loaded/registered')
exports = np.exports(data, image)
require('_vfs_fsadd' in exports.get(int(registered['finished_function_entry'], 16), []), 'actual source VFS registration entry')
require(registered['function_return_stack_matched'] and registered['sp'] == registered['function_entry_stack'] and
        registered['pc'] == registered['function_return_target'] and int(registered['x0'], 16) == 0,
        'actual same-stack VFS registration returned zero')
text = next(e for e in positive['extents'] if e['module'] == 'com.apple.filesystems.apfs' and e['segment'] == '__TEXT_EXEC')
require(text['va'] <= int(registered['pc'], 16) < text['va'] + text['size'], 'real VFS registration caller belongs to original APFS')


def layout(name):
    obj = build / 'mockfs-fixture/mockfs_vfsops.o'
    dwarf = subprocess.check_output(['xcrun', 'dwarfdump', '--name=' + name, '--show-children', obj], text=True)
    offsets = {}
    for member in dwarf.split('DW_TAG_member')[1:]:
        field = re.search(r'DW_AT_name\s+\("([^"]+)"\)', member)
        offset = re.search(r'DW_AT_data_member_location\s+\((0x[0-9a-f]+)\)', member)
        if field and offset:
            offsets[field[1]] = int(offset[1], 16)
    return offsets


table_layout, ops_layout = layout('vfstable'), layout('vfsops')
require(table_layout['vfc_vfsops'] == 0 and table_layout['vfc_name'] == 8, 'compiled actual VFS table ABI')
ops = registered['entry_indirect_memory']['0:0:90']
table = registered['entry_indirect_memory']['1:0:80']
ops_address = int(ops['pointer'], 16)
table_bytes = bytes.fromhex(table['bytes'])
require(struct.unpack_from('<Q', table_bytes, table_layout['vfc_vfsops'])[0] == ops_address and
        table_bytes[table_layout['vfc_name']:].split(b'\0', 1)[0] == b'apfs', 'actual returned table names apfs and retains original operations')
ops_bytes = bytes.fromhex(ops['bytes'])
at = np.backed_offset(image['segments'], ops_address, len(ops_bytes), len(data))
require(ops_bytes == data[at:at + len(ops_bytes)], 'actual observed operations match the unchanged original table')
functions = {}
for name in ('vfs_mount', 'vfs_unmount', 'vfs_root', 'vfs_getattr', 'vfs_sync'):
    pointer = struct.unpack_from('<Q', ops_bytes, ops_layout[name])[0]
    require(text['va'] <= pointer < text['va'] + text['size'], 'original APFS operation pointer for ' + name)
    functions[name] = hex(pointer)
result = dict(candidate_sha256=positive['candidate_sha256'], missing_candidate_sha256=negative['candidate_sha256'],
              checked_qemu_reports=3, genuine_apfs_kmod_executed=True, actual_vfs_fsadd_return=0,
              actual_registered_name='apfs', actual_vfstable=table['pointer'], actual_vfsops=ops['pointer'],
              actual_original_operations=functions, compiled_vfstable_offsets=table_layout,
              compiled_vfsops_offsets=ops_layout, native_4k=True, original_executable_code_unchanged=True,
              missing_module_refused=True, block_device_read_tested=False, apfs_container_mounted=False,
              functional_ipados_booted=False, hardware_tested=False)
(build / 'original-apfs-checkpoints.json').write_text(json.dumps(result, indent=2) + '\n')
print('PASS: original APFS kmod executes; genuine VFS registration returns 0 with actual apfs/original operations')
print('Active hardware translation is native 4K; disk reads, container mount, iPadOS UI and sheng hardware remain unqualified')
