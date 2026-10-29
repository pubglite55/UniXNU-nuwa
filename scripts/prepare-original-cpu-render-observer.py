#!/usr/bin/env python3
"""Bind read-only original CPU-render observations to a qualified kernel/cache.

The layout plan must have been qualified for this exact native kernel, and its
four compiler objects must still match. This accepts retained prelink candidates
without silently borrowing the offsets/entrypoints of a subsequently rebuilt one.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--kernel', type=Path, required=True)
p.add_argument('--prelink-report', type=Path, required=True)
p.add_argument('--layout-plan', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
mode = p.add_mutually_exclusive_group()
mode.add_argument('--trace', action='store_true')
mode.add_argument('--frame-path', action='store_true', help='Observe real renderer construction, CPU drawing and framebuffer submission')
mode.add_argument('--gates', action='store_true', help='Observe actual display enabled/update/ready decisions')
mode.add_argument('--composition', action='store_true', help='Observe original update filtering and damage decisions')
mode.add_argument('--mode-state', action='store_true', help='Observe original framebuffer mode inputs and update-filter state')
a = p.parse_args()
plan = json.loads(a.layout_plan.read_text())
report = json.loads(a.prelink_report.read_text())

def require(condition, message):
    if not condition:
        raise SystemExit(message)

require(plan['native_sha256'] == report['native_sha256'], 'Layout plan belongs to a different native kernel')
require(hashlib.sha256(a.kernel.read_bytes()).hexdigest() == report['candidate_sha256'], 'Candidate differs from prelink report')
require(plan['original_files_modified'] is False, 'Original images must remain unchanged')
objects = ROOT / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
for key, relative in [('thread', 'osfmk/DEVELOPMENT/thread.o'), ('proc', 'bsd/DEVELOPMENT/kern_proc.o'),
                      ('task', 'osfmk/DEVELOPMENT/task.o'), ('region', 'osfmk/DEVELOPMENT/vm_shared_region.o')]:
    require(hashlib.sha256((objects / relative).read_bytes()).hexdigest() == plan['process_layout'][key + '_object_sha256'],
            'Compiler layout object changed: ' + key)
launchd = ROOT / '.cache/firmware/target-volumes/os-mount/sbin/launchd'
require(hashlib.sha256(launchd.read_bytes()).hexdigest() == plan['launchd_sha256'] ==
        '8cec9a3c44a443b08e977ccc5d577850316ad428c575dc01f09b018dbd5b6a25', 'Original launchd differs')
cache = ROOT / '.cache/firmware/target-volumes/systemos-mount/System/Library/Caches/com.apple.dyld'
with (cache / 'dyld_shared_cache_arm64').open('rb') as f:
    header = f.read(416)
require(header[88:104].hex() == plan['cache_uuid'] == '590d839a82d230f1a17d0cc053420f73', 'Original cache UUID differs')
require(header[400:416].hex() == plan['local_symbols_uuid'] == 'a1a859a2479c31998a34f4afbd808cf5', 'Original symbol UUID differs')
specs = [
    ('display_timer', 0x1894f5a0c, 0x3d8, '9d2dd9e0c74e07f519709ce39629fbfe4399fb4774c18ea4273a76a3ce8b3b20'),
    ('render_for_time', 0x18951dde0, 0x3f1c, '94cae733f1ee23252d773b75d701077f85c07417b7647da214f208e7d09cec4a'),
    ('render_update', 0x1894c5eb0, 0xac, 'b63dc0ec6492a9e1a7343f91bc7bae0f3a710ce2c2b13081931a7c4a646e745f'),
    ('software_renderer', 0x1896a880c, 0x1d8, '8b6a57aa9f177cc237b23123fba8033254b8ad5d03f37de221febdb4bdf0a821'),
    ('can_update', 0x189509d88, 0xb8, '083e024d55d67a0950c0a0f3665f3a553fbed0115c413a6391ce2da10ff41bd7'),
    ('is_ready', 0x189510848, 0x88, '6b946552ee020aca1c74dd310acb89403f62a6a6c85e9836f5c941a807ebb518'),
    ('ignore_update', 0x18952288c, 0x5c, '5df7f40779b4a601c4f8f55319ec00bde52b8b140a74b33fee89d4512df695f1'),
    ('update_framebuffer', 0x189596aec, 0x20fc, 'eeae0b7e58ac0d9225ad0e5658ace97f930b3d29632639637634dd80f5db1067'),
    ('render_display', 0x1894c60e0, 0x340, '33dcc0cbda369b002c2c669a2c55518761bbf3623901064ac182b529fb5f74ba'),
    ('software_draw_elements', 0x189616220, 0x17ac, 'cfabb66aafc1f4744400d4ee3917b1c517a1a98f15859785cccf62b6525034ab'),
    ('framebuffer_swap_end', 0x1b63cfc94, 0x1c, 'e34e888204aa63584884512f17a59a579456219676dd23b120424b425fd88815'),
]
found = {}
gate_prefixes = {}
for file in sorted(cache.glob('dyld_shared_cache_arm64*')):
    if file.suffix == '.symbols':
        continue
    with file.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        require(data[:16].rstrip(b'\0') == b'dyld_v1   arm64', 'Require ordinary ARM64 cache')
        at, count = struct.unpack_from('<2I', data, 16)
        for index in range(count):
            va, size, offset, _, protection = struct.unpack_from('<3Q2I', data, at + index * 32)
            for name, address, length, digest in specs:
                if va <= address and address + length <= va + size:
                    body = data[offset + address - va:offset + address - va + length]
                    require(protection & 4 and hashlib.sha256(body).hexdigest() == digest, 'Original function differs: ' + name)
                    require(name not in found, 'Ambiguous executable cache mapping')
                    found[name] = dict(name=name, address=address, length=length, sha256=digest, prefix=body[:16].hex())
                    if name == 'software_renderer':
                        require(body[0x1d0:0x1d4] == bytes.fromhex('c0035fd6'), 'Original software renderer RET differs')
                        renderer_return_prefix = data[offset + address - va + 0x1d0:offset + address - va + 0x1e0].hex()
                    for gate, parent, delta in [('can_update_enabled_result', 'can_update', 0x30),
                                                 ('can_update_return', 'can_update', 0x90),
                                                 ('is_ready_return', 'is_ready', 0x7c),
                                                 ('ignore_update_result', 'render_for_time', 0x1194),
                                                 ('damage_comparison', 'render_for_time', 0x1250)]:
                        if name == parent:
                            # Prefix may span the function's final RET. Read it
                            # from the same real executable cache mapping.
                            start = offset + address - va + delta
                            gate_prefixes[gate] = data[start:start + 16].hex()
require(len(found) == len(specs), 'Original render functions are missing')
symbols = subprocess.check_output(['xcrun', 'nm', '-U', a.kernel], text=True, timeout=30)
plan['process_activation'] = []
for name in ('_shared_region_check_np', '_shared_region_map_and_slide_2_np'):
    match = re.search(r'^([0-9a-f]+)\s+\S\s+' + name + '$', symbols, re.M)
    require(match is not None, 'Candidate shared-region entrypoint is missing')
    plan['process_activation'].append(int(match[1], 16))
for key in ('port_checkpoint', 'reply_checkpoint', 'main_display', 'displays', 'cas_request_id', 'original_mode_initializer_sha256', 'trace_sites'):
    plan.pop(key, None)
site = found['software_renderer']
plan.update(mode='user-trace' if a.trace or a.gates or a.composition or a.mode_state or a.frame_path else 'user-return', expected_process='backboardd', query=site['address'],
            query_prefix=site['prefix'], return_checkpoint=0x1d0, object_bytes=104, original_function_sha256=site['sha256'],
            candidate_sha256=report['candidate_sha256'], purpose='Unchanged original backboardd CPU-render path; read-only observation')
plan['max_activation_events'] = 2048
if a.trace:
    plan['trace_sites'] = [found[name] for name, *_ in specs[:4]]
if a.frame_path:
    plan['trace_sites'] = [dict(name='software_renderer_return',
        address=found['software_renderer']['address'] + 0x1d0,
        prefix=renderer_return_prefix, parent_function=found['software_renderer'],
        memory_reads=[dict(register=0, offset=0, size=104, indirect=False)]),
        *[found[name] for name in ('render_display', 'software_draw_elements', 'framebuffer_swap_end')]]
if a.gates:
    plan['trace_sites'] = []
    for name, parent, delta, register in [('can_update_enabled_result', 'can_update', 0x30, 20),
                                         ('can_update_return', 'can_update', 0x90, 20),
                                         ('is_ready_return', 'is_ready', 0x7c, 19)]:
        # Addresses/fields follow the above hash-qualified original bodies.
        # These are observations, never replacements for the original checks.
        parent_site = found[parent]
        plan['trace_sites'].append(dict(name=name, address=parent_site['address'] + delta,
            prefix=gate_prefixes[name], max_hits=8, parent_function=parent_site,
            memory_reads=[dict(register=register, offset=offset, size=size, indirect=indirect)
                for offset, size, indirect in [(0,64,False), (0x248,8,False), (0x290,16,True), (0x6bcd,32,False)]]))
    plan['trace_sites'].append(found['render_update'])
if a.composition:
    plan['trace_sites'] = []
    for name, delta in [('ignore_update_result', 0x1194), ('damage_comparison', 0x1250)]:
        parent_site = found['render_for_time']
        plan['trace_sites'].append(dict(name=name, address=parent_site['address'] + delta,
            prefix=gate_prefixes[name], max_hits=8, parent_function=parent_site,
            memory_reads=[dict(register=19, offset=offset, size=size, indirect=indirect)
                for offset, size, indirect in [(0x3d0,256,False), (0x4d4,4,False), (0x1f0,256,True),
                                               (0x4b0,8,False), (0xc8,8,False)]]))
    plan['trace_sites'] += [found['render_update'], found['software_renderer']]
if a.mode_state:
    plan['trace_sites'] = []
    for name in ('update_framebuffer', 'ignore_update'):
        # Both exact original function entries take the display in x0. Capture
        # mode source/current/selected state and the shared readiness flags.
        # A sentinel value alone is not proof of an invalid hardware mode.
        site = dict(found[name], max_hits=8,
            memory_reads=[dict(register=0, offset=offset, size=size, indirect=indirect)
                for offset, size, indirect in [(0x240,48,False), (0x68e0,64,False),
                                               (0x6bc0,64,False), (0x290,16,True)]])
        if name == 'ignore_update':
            site['memory_reads'].append(dict(register=1, offset=0x100, size=16, indirect=False))
        plan['trace_sites'].append(site)
    plan['trace_sites'] += [found['render_update'], found['software_renderer']]
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(plan, indent=2) + '\n')
print('PASS: original render bytes, cache identity, compiled process layout and exact candidate entrypoints')
