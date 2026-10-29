#!/usr/bin/env python3
"""Check real read-only descriptor DMA, separately from storage publication."""
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


def require(value, message):
    if not value:
        raise SystemExit('FAIL: ' + message)


build = ROOT / 'build'
kernel = build / 'xnu-prelink/native-virtio-firstread-candidate.macho'
data = kernel.read_bytes()
plan = json.loads(kernel.with_suffix('.json').read_text())
require(hashlib.sha256(data).hexdigest() == plan['candidate_sha256'] ==
        '213d08f953fe38d6b2aab67a2de78aafb2d15af76bbd2cc7582358597a161e5a', 'exact observed candidate')
require(plan['native_sha256'] == 'e0f9be317b31c53582802746fb792c45f7d14a554f00dac6deaec701b2636c1b' and
        plan['original_sha256'] == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7' and
        not plan['source_inputs_modified'] and not plan['images_modified'], 'native and original input provenance')
image = np.macho(data)
require(struct.unpack_from('<I', data, 8)[0] == 0, 'ordinary ARM64 subtype')
for extent in plan['extents']:
    if extent['segment'] == '__TEXT_EXEC':
        at = np.backed_offset(image['segments'], extent['va'], extent['size'], len(data))
        require(hashlib.sha256(data[at:at + extent['size']]).hexdigest() ==
                plan['original_executable_sha256'][extent['module']], 'unchanged original executable extent')


def report(name):
    d = json.loads((build / name / 'gdb-stop.json').read_text())
    require(d['kernel_sha256'] == plan['candidate_sha256'] and not d['bounded_timeout_interrupted'], 'bounded candidate observation')
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'], 'active native 4K translation roots')
    return d


read = report('darwinboot-virtio-firstread')
configured = report('darwinboot-virtio-platform-configure')
require(read['stop_symbol'] == '_native_virtio_read_checkpoint' and read['original_crypto_initialized_observed'], 'actual read checkpoint and original crypto')
require(configured['function_return_stack_matched'] and configured['sp'] == configured['function_entry_stack'] and
        configured['pc'] == configured['function_return_target'] and int(configured['x0'], 16) == 1, 'actual platform configure returns true on same stack')
for d in (read, configured):
    g = d['armvirt_globals']
    require(g['_armvirt_platform_configured'] == 1 and g['_armvirt_platform_child_count'] == 37 and
            all(g['_armvirt_platform_' + n + '_count'] == 1 for n in ('cpu', 'bus', 'defaults')), 'actual platform resource enumeration')
g = read['native_virtio_globals']
require(g['_native_virtio_ready'] == 1 and g['_native_virtio_read_requests'] == 1 and
        g['_native_virtio_read_failures'] == 0, 'one genuine successful DMA request')
raw = ROOT / '.cache/firmware/target-volumes/044-76034-038.dmg'
with raw.open('rb') as stream:
    sector = stream.read(512)
digest = hashlib.sha256(sector).hexdigest()
input_record = read['virtio_block_input']
require(input_record['read_only'] and input_record['format'] == 'raw' and
        input_record['name'] == raw.name and input_record['bytes'] == raw.stat().st_size == 3303014400 and
        g['_native_virtio_sectors'] * 512 == raw.stat().st_size, 'real read-only input and device capacity')
require(sector[32:36] == b'NXSB' and digest == read['native_virtio_first_sector_sha256'] ==
        input_record['first_sector_sha256'] == '42b1178767bb27611cd1836cdd5779c48bfca8a3e719ec06dc4c8ef78d5e6387', 'actual DMA data matches original raw sector')
fdt = build / 'virtio-block-fixture/qemu-virt.dtb'
dts = subprocess.check_output(['dtc', '-I', 'dtb', '-O', 'dts', str(fdt)], text=True, stderr=subprocess.DEVNULL)
windows = []
for node in re.findall(r'virtio_mmio@[0-9a-f]+\s*\{([^}]+)\}', dts):
    match = re.search(r'reg = <([^>]+)>', node)
    if match and 'dma-coherent;' in node and '"virtio,mmio"' in node:
        cells = [int(v, 16) for v in match[1].split()]
        require(len(cells) == 4, 'actual FDT two-cell address and size')
        windows.append(((cells[0] << 32) | cells[1], (cells[2] << 32) | cells[3]))
require(len(windows) == 32 and (g['_native_virtio_mmio_physical'], 0x200) in windows, 'discovered active address belongs to actual coherent FDT resources')
bindings = json.loads((build / 'virtio-mmio-block/bindings.json').read_text())
require(bindings['virtual_methods_checked'] == 190 and bindings['concrete_overrides'] == 25 and
        bindings['unresolved_original_imports'] == 0 and len(bindings['bindings']) == 11 and
        not bindings['original_code_modified'], 'qualified original storage dispatch and C2/D2 imports')
media = json.loads((build / 'darwinboot-virtio-media-properties/gdb-stop.json').read_text())
require(media['kernel_sha256'] == plan['candidate_sha256'] and media['bounded_timeout_interrupted'] and
        not media['registry_string_log_exhausted'], 'bounded media observation with complete property log')
properties = media['registry_string_events']
volume_uuid = '8846FE78-2910-4297-AF97-D59BB6F8FC16'
uuid_event = next(e for e in properties if e['key'] == 'UUID' and e['value'] == volume_uuid)
volume = uuid_event['entry']
volume_properties = {e['key']: e['value'] for e in properties if e['entry'] == volume}
require(volume_properties['Status'] == 'Online' and volume_properties['BSD Name'] == 'disk1s1' and
        volume_properties['Content'] == '41504653-0000-11AA-AA11-00306543ECAC' and
        volume_properties['Sealed'] == 'Yes', 'actual original APFS volume publication')
apfs = next(e for e in plan['extents'] if e['module'] == 'com.apple.filesystems.apfs' and e['segment'] == '__TEXT_EXEC')
require(apfs['va'] <= int(uuid_event['caller'], 16) < apfs['va'] + apfs['size'], 'volume UUID published by unchanged original APFS')
exports = np.exports(data, image)
read_method = '__ZN17NativeVirtioBlock16doAsyncReadWriteEP18IOMemoryDescriptoryyP19IOStorageAttributesP19IOStorageCompletion'
require(any(read_method in exports.get(int(e['pc'], 16), []) for e in media['trace_events']), 'actual public storage request executed')
symbol_output = subprocess.check_output(['xcrun', 'nm', '-U', str(kernel)], text=True)
symbols = {n: int(a, 16) for a, n in re.findall(r'^([0-9a-fA-F]+)\s+\S\s+(\S+)$', symbol_output, re.M)}
def observed(name):
    size = 8 if name.endswith(('sectors', 'physical')) else 4
    return int.from_bytes(bytes.fromhex(media['memory'][f'{symbols[name]:x}:{size:x}']), 'little')
require(observed('_native_virtio_read_requests') == 62 and observed('_native_virtio_read_failures') == 0 and
        observed('_native_virtio_ready') == 1, 'actual storage stack completed 62 reads without DMA failure')
result = dict(candidate_sha256=plan['candidate_sha256'], native_sha256=plan['native_sha256'],
              checked_qemu_reports=3, read_only=True, first_sector_sha256=digest,
              input_bytes=raw.stat().st_size, capacity_sectors=g['_native_virtio_sectors'],
              discovered_mmio_physical=hex(g['_native_virtio_mmio_physical']),
              fdt_sha256=hashlib.sha256(fdt.read_bytes()).hexdigest(),
              actual_descriptor_dma_observed=True, native_4k=True,
              original_executable_code_unchanged=True, platform_configure_return=1,
              public_storage_read_observed=True, completed_dma_reads=62,
              iomedia_attachment_qualified=True, volume_uuid=volume_uuid, observed_bsd_name='disk1s1',
              apfs_mount_qualified=False,
              functional_ipados_booted=False, hardware_tested=False)
(build / 'native-virtio-checkpoints.json').write_text(json.dumps(result, indent=2) + '\n')
print('PASS: real read-only VirtIO DMA matches original SystemOS sector; native 4K and actual platform return verified')
print('Original APFS publishes the matching Online SystemOS volume after 62 real reads; mount, iPadOS UI and hardware remain unqualified')
