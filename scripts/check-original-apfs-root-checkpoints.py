#!/usr/bin/env python3
"""Check original OS root mount and preserve the sealed Cryptex root refusal."""
import json
import hashlib
from pathlib import Path
import plistlib
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
build = ROOT / 'build'


def require(value, message):
    if not value:
        raise SystemExit('FAIL: ' + message)


for script in ('check-native-virtio-checkpoints.py', 'check-original-apfs-checkpoints.py'):
    subprocess.run(['python3', ROOT / 'scripts' / script], check=True)
plan = json.loads((build / 'xnu-prelink/native-virtio-firstread-candidate.json').read_text())
qualified = json.loads((build / 'original-apfs-checkpoints.json').read_text())
operation = qualified['actual_original_operations']['vfs_mount']


def report(name, timed_out=False, candidate=plan['candidate_sha256']):
    d = json.loads((build / name / 'gdb-stop.json').read_text())
    require(d['kernel_sha256'] == candidate and d['bounded_timeout_interrupted'] == timed_out,
            'exact candidate and explicit observation deadline')
    r = {k: int(v, 16) for k, v in d['system_registers'].items()}
    require(r['TCR_EL1'] >> 14 & 3 == 0 and r['TCR_EL1'] >> 30 & 3 == 2 and
            r['SCTLR_EL1'] & 1 and r['TTBR0_EL1'] and r['TTBR1_EL1'], 'active native 4K hardware roots')
    return d


media = report('darwinboot-virtio-original-os-media', True)
mounted = report('darwinboot-virtio-original-os-bsd-mount')
refused = report('darwinboot-virtio-apfs-bsd-mount')
rootauth = report('darwinboot-original-os-dyld-prepare')
for d in (media, mounted):
    i = d['virtio_block_input']
    require(i['name'] == '044-76040-038.dmg' and i['source_format'] == 'UDIF' and
            i['source_sha256'] == '3f99b859c9728379110b66657c7b15285bcb1925ad8b5726542e2cdcf8b1028d' and
            i['source_bytes'] == 5157406069 and i['bytes'] == 6077580800 and
            i['read_only'] and i['host_bus_protocol'] == 'Disk Image' and
            i['host_media_writable'] is False, 'exact supplied OS image through actual read-only virtual media')
require(not media['registry_string_log_exhausted'], 'complete bounded original OS property observation')
properties = media['registry_string_events']
volume_uuid = '04769D26-2CA0-4825-B443-E2E5F88300F2'
entry = next(e['entry'] for e in properties if e['key'] == 'UUID' and e['value'] == volume_uuid)
v = {e['key']: e['value'] for e in properties if e['entry'] == entry}
require(v['Status'] == 'Online' and v['Sealed'] == 'No' and v['BSD Name'] == 'disk1s1' and
        v['FullName'] == 'DawnUpdate21H461.J120J121J207J208OS', 'actual original OS volume publication')
config = (build / 'darwinboot-virtio-original-os-bsd-mount/esp/EFI/UniXNU/unixnu.toml').read_text()
require('rd=' + v['BSD Name'] + ' ' in config and 'initrd =' not in config, 'root chosen from actual published volume; no RAM root')
require(mounted['finished_function_entry'] == operation and mounted['function_return_stack_matched'] and
        mounted['sp'] == mounted['function_entry_stack'] and mounted['pc'] == mounted['function_return_target'] and
        int(mounted['x0'], 16) == 0, 'genuine original APFS mount returns zero on same stack')
g = mounted['native_virtio_globals']
require(g['_native_virtio_ready'] == 1 and g['_native_virtio_read_requests'] == 167 and
        g['_native_virtio_read_failures'] == 0 and g['_native_virtio_sectors'] * 512 == 6077580800,
        'actual OS root mount disk reads and capacity')
require(mounted['original_crypto_initialized_observed'], 'genuine original crypto remains initialized')
require(refused['finished_function_entry'] == operation and not refused['function_return_stack_matched'] and
        'Failed to find the root snapshot' in refused['argument_memory']['x0'] and
        'Rooting from the live fs of a sealed volume is not allowed on a RELEASE build' in refused['argument_memory']['x0'],
        'original sealed SystemCryptex root refusal retained')
apfs = next(e for e in plan['extents'] if e['module'] == 'com.apple.filesystems.apfs' and e['segment'] == '__TEXT_EXEC')
require(apfs['va'] <= int(refused['x30'], 16) < apfs['va'] + apfs['size'], 'actual refusal caller belongs to original APFS')
symbols = subprocess.check_output(['xcrun', 'nm', '-U', build / 'xnu-prelink/native-virtio-firstread-candidate.macho'], text=True)
panic = re.search(r'^([0-9a-f]+)\s+\S\s+_panic$', symbols, re.M)
require(panic and int(refused['pc'], 16) == int(panic[1], 16), 'genuine source panic receives original APFS refusal')
require(int(rootauth['pc'], 16) == int(panic[1], 16) and
        rootauth['argument_memory']['x0'] == 'rootvp not authenticated after mounting @%s:%d' and
        not rootauth.get('followed_user_entry') and not rootauth['syscall_events'] and
        rootauth['kernel_observations']['_native_virtio_read_requests'] == 167 and
        rootauth['kernel_observations']['_native_virtio_read_failures'] == 0,
        'genuine post-mount root authentication refuses the unsealed restore volume before userspace')
matched_kernel = build / 'xnu-prelink/native-apfs-data-candidate.macho'
matched_plan = json.loads(matched_kernel.with_suffix('.json').read_text())
require(hashlib.sha256(matched_kernel.read_bytes()).hexdigest() == matched_plan['candidate_sha256'] ==
        '8db7506164cb7772c6af3e8bd21b4a9ee3a951c5c611550deae923ed1558628f' and
        matched_plan['original_executable_sha256'] == plan['original_executable_sha256'], 'exact UUID-match candidate retains the same original modules')
matched = report('darwinboot-original-os-uuid-match-mount', candidate=matched_plan['candidate_sha256'])
require(matched['finished_function_entry'] == operation and matched['function_return_stack_matched'] and
        matched['pc'] == matched['function_return_target'] and matched['sp'] == matched['function_entry_stack'] and
        int(matched['x0'], 16) == 0, 'actual UUID-selected original mount returns zero on same stack')
selection = matched['root_selection']
require(selection['volume_uuid'] == volume_uuid and not selection['bsd_name_override'] and
        not selection['root_authentication_bypassed'], 'volume matching preserves authentication policy')
matched_dir = build / 'darwinboot-original-os-uuid-match-mount/esp/EFI/UniXNU'
config = (matched_dir / 'unixnu.toml').read_text()
require('rd=' not in config and 'boot-uuid=' not in config and 'initrd =' not in config, 'no BSD-name/resource/RAM override')
tree = (matched_dir / 'Payloads/kernel.macho.adt').read_bytes()


def dt_node(at):
    count, children = struct.unpack_from('<II', tree, at)
    at += 8
    properties = {}
    for _ in range(count):
        key, size = struct.unpack_from('<32sI', tree, at)
        at += 36
        properties[key.rstrip(b'\0').decode()] = tree[at:at + size]
        at += (size + 3) & ~3
    descendants = []
    for _ in range(children):
        child, at = dt_node(at)
        descendants.append(child)
    return (properties, descendants), at


(properties, children), end = dt_node(0)
require(end == len(tree), 'actual loaded DT byte extent')
chosen = next(p for p, _ in children if p['name'] == b'chosen\0')
matching = plistlib.loads(b'<plist version="1.0">' + chosen['root-matching'].rstrip(b'\0') + b'</plist>')
require(matching == {'IOProviderClass': 'IOMedia', 'IOPropertyMatch': {'UUID': volume_uuid}}, 'actual DT selector matches only the original published volume UUID')
require(matched['native_virtio_globals']['_native_virtio_read_requests'] == 167 and
        matched['native_virtio_globals']['_native_virtio_read_failures'] == 0, 'actual UUID-root mount I/O')
result = dict(candidate_sha256=plan['candidate_sha256'], checked_qemu_reports=5,
              original_os_volume_uuid=volume_uuid, observed_bsd_name=v['BSD Name'],
              original_apfs_mount_entry=operation, same_stack_mount_return=0, native_4k=True,
              read_only_os_virtual_media=True, os_mount_completed_reads=167,
              sealed_cryptex_root_refused=True, original_code_modified=False,
              os_vfs_mount_completed=True, root_authentication_enforced=True,
              unsealed_os_root_authentication_refused=True,
              uuid_match_candidate_sha256=matched_plan['candidate_sha256'],
              direct_uuid_root_match_qualified=True, uuid_match_mount_return=0,
              original_userspace_executed_from_apfs_qualified=False,
              functional_ipados_booted=False, hardware_tested=False)
(build / 'original-apfs-root-checkpoints.json').write_text(json.dumps(result, indent=2) + '\n')
print('PASS: original supplied OS APFS root mount returns 0 under native 4K after 167 successful DMA reads')
print('Sealed Cryptex root and unauthenticated OS root are genuinely refused; no APFS userspace/UI boot is claimed')
print('Standard DT matching also mounts the real UUID-selected volume without a BSD-name override')
