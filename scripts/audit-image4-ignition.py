#!/usr/bin/env python3
"""Locate the unchanged target Image4 ignition handler and its real kernel calls."""
import argparse
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

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--candidate', type=Path, default=ROOT / 'build/xnu-prelink/native-defaults-candidate.macho')
parser.add_argument('--output', type=Path, default=ROOT / 'build/image4-ignition/audit.json')
args = parser.parse_args()
original = (ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed').read_bytes()
if hashlib.sha256(original).hexdigest() != 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7':
    raise SystemExit('Unexpected supplied ordinary ARM64 original kernel')
candidate = args.candidate.read_bytes()
plan = json.loads(args.candidate.with_suffix('.json').read_text())
if hashlib.sha256(candidate).hexdigest() != plan['candidate_sha256']:
    raise SystemExit('Candidate identity mismatch')
parent, native = np.macho(original), np.macho(candidate)
info = next(s for s in parent['segments'] if s['name'] == '__PRELINK_INFO')
at = np.backed_offset(parent['segments'], info['va'], info['filesize'], len(original))
entry = next(e for e in np.unserialize_xml(original[at:at + info['filesize']])['_PrelinkInfoDictionary']
             if e['CFBundleIdentifier'] == 'com.apple.security.AppleImage4')
at = np.backed_offset(parent['segments'], entry['_PrelinkExecutableLoadAddr'], 32, len(original))
module = np.macho(original, at)


def read(image, segments, va, length):
    at = np.backed_offset(segments, va, length, len(image))
    return image[at:at + length]


obj = ROOT / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/kern_newsysctl.o'
dwarf = subprocess.check_output(['xcrun', 'dwarfdump', '--name=sysctl_oid', '--show-children', obj], text=True)
layout = {}
for member in dwarf.split('DW_TAG_member')[1:]:
    name = re.search(r'DW_AT_name\s+\("([^"]+)"\)', member)
    offset = re.search(r'DW_AT_data_member_location\s+\((0x[0-9a-f]+)\)', member)
    if name and offset:
        layout[name[1]] = int(offset[1], 16)
if (layout.get('oid_name'), layout.get('oid_handler')) != (40, 48):
    raise SystemExit('Unexpected actual compiled sysctl_oid ABI')
strings = []
for s in module['segments']:
    if s['name'] == '__TEXT':
        data = read(original, parent['segments'], s['va'], s['filesize'])
        strings += [s['va'] + m.start() for m in re.finditer(b'ignition_blob\x00', data)]
if len(strings) != 1:
    raise SystemExit('Expected exactly one original ignition_blob name')
oids = []
for s in module['segments']:
    if s['name'] in ('__DATA', '__DATA_CONST'):
        data = read(original, parent['segments'], s['va'], s['filesize'])
        for at in range(0, len(data) - 7, 8):
            if struct.unpack_from('<Q', data, at)[0] == strings[0]:
                oids.append(s['va'] + at - layout['oid_name'])
if len(oids) != 1:
    raise SystemExit('Expected exactly one original sysctl object')
handler = struct.unpack('<Q', read(original, parent['segments'], oids[0] + layout['oid_handler'], 8))[0]
text = next(s for s in module['segments'] if s['name'] == '__TEXT_EXEC')
if not text['va'] <= handler < text['va'] + text['filesize']:
    raise SystemExit('Handler is outside original executable text')
slid = handler + plan['slide']
prefix = read(candidate, native['segments'], slid, 0xc0)
if prefix != read(original, parent['segments'], handler, len(prefix)):
    raise SystemExit('Original handler code was changed')
exports = np.exports(candidate, native)
bindings = {b['new_site']: b for b in plan['bindings'] if b['kind'] == 'kernel'}
calls = []
for offset in range(0, len(prefix), 4):
    instruction = struct.unpack_from('<I', prefix, offset)[0]
    if instruction & 0xfc000000 != 0x94000000:
        continue
    immediate = instruction & 0x3ffffff
    if immediate & 0x2000000:
        immediate -= 0x4000000
    target = slid + offset + immediate * 4
    a, load, branch = struct.unpack('<3I', read(candidate, native['segments'], target, 12))
    if a & 0x9f00001f != 0x90000010 or load & 0xffc003ff != 0xf9400210 or branch != 0xd61f0200:
        continue
    delta = ((a >> 5 & 0x7ffff) << 2) | (a >> 29 & 3)
    if delta & 0x100000:
        delta -= 0x200000
    got = (target & ~4095) + delta * 4096 + (load >> 10 & 4095) * 8
    if got in bindings:
        destination = bindings[got]['new_target']
        calls.append(dict(site=hex(slid + offset), target=hex(destination), names=exports.get(destination, [])))
wait = [c for c in calls if '_lck_mtx_gate_wait' in c['names']]
if len(wait) != 1:
    raise SystemExit('Cannot establish the real source-kernel gate-wait binding')
result = dict(original_sha256=hashlib.sha256(original).hexdigest(), candidate_sha256=plan['candidate_sha256'],
              original_handler=hex(handler), candidate_handler=hex(slid), oid=hex(oids[0]),
              compiled_oid_offsets={k: layout[k] for k in ('oid_name', 'oid_handler')},
              original_handler_prefix_sha256=hashlib.sha256(prefix).hexdigest(), kernel_calls=calls,
              personality=entry['IOKitPersonalities']['AppleImage4'],
              code_or_security_result_modified=False, source_analysis_only=True, handler_return_observed=False)
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(result, indent=2) + '\n')
print('PASS: actual original sysctl object/handler, compiled ABI, unchanged code and genuine gate-wait binding')
print(f'Handler {slid:#x}; gate wait {wait[0]["target"]}; this is static analysis, not service startup')
