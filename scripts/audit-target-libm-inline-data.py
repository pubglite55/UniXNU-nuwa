#!/usr/bin/env python3
"""Qualify unchanged inline math pools and actual-image prelink refusal controls."""
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import backed_offset, macho, unserialize_xml
from emit_prelink import instruction_inventory, pc_relative_target, MATH_LITERAL_POOLS

source = ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed'
data = source.read_bytes()
expected = 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7'
if hashlib.sha256(data).hexdigest() != expected:
    raise SystemExit('Require the unchanged supplied original kernelcache')
parent = macho(data)['segments']
info = next(s for s in parent if s['name'] == '__PRELINK_INFO')
at = backed_offset(parent, info['va'], info['filesize'], len(data))
entries = {e['CFBundleIdentifier']: e for e in unserialize_xml(data[at:at + info['filesize']])['_PrelinkInfoDictionary']}
plan = json.loads((ROOT / 'build/display-analysis/mobile-graphics-plan.json').read_text())
modules = {name: macho(data, backed_offset(parent, entries[name]['_PrelinkExecutableLoadAddr'], 32, len(data)))
           for name in plan['components']}
module = modules['com.apple.kec.Libm']
text = next(s for s in module['segments'] if s['name'] == '__TEXT_EXEC')
at = backed_offset(parent, text['va'], text['filesize'], len(data))
blob = data[at:at + text['filesize']]
ranges = [(0x350, 0xbc0), (0xf60, 0x1440), (0x1884, 0x2110), (0x21e8, 0x2628), (0x280c, 0x28e0), (0x3010, 0x3048)]
records = []
for (start, end), (prefix, size, digest) in zip(ranges, MATH_LITERAL_POOLS):
    pool = blob[start:end]
    if len(pool) != size or not pool.startswith(bytes.fromhex(prefix)) or hashlib.sha256(pool).hexdigest() != digest:
        raise SystemExit('Complete original math-pool identity differs')
    previous = blob[start - 4:start]
    if previous != bytes.fromhex('c0035fd6') or blob[end:end + 4] != bytes.fromhex('fd7bbfa9'):
        raise SystemExit('Require original RET/data/next-function boundaries')
    references, incoming_branches = [], []
    for offset in range(0, len(blob) - 3, 4):
        if any(a <= offset < b for a, b in ranges):
            continue
        word, = struct.unpack_from('<I', blob, offset)
        decoded = pc_relative_target(word, text['va'] + offset)
        if decoded is None or decoded[1] or not text['va'] + start <= decoded[0] < text['va'] + end:
            continue
        row = dict(pc=hex(text['va'] + offset), word=hex(word), target=hex(decoded[0]))
        if word & 0x9f000000 == 0x10000000 or word & 0x3b000000 == 0x18000000:
            references.append(row)
        else:
            incoming_branches.append(row)
    if not references or incoming_branches:
        raise SystemExit('Math data must have actual ADR/literal-load references and no observed direct code branch into it')
    records.append(dict(va=hex(text['va'] + start), bytes=size, sha256=digest, references=references,
                        incoming_direct_branches=incoming_branches))

highs = [struct.unpack_from('<d', blob, 0x3c0 + i * 16)[0] for i in range(128)]
max_ulps = max(abs(value - 2 ** (i / 128)) / math.ulp(2 ** (i / 128)) for i, value in enumerate(highs))
if max_ulps > 1 or any(a >= b for a, b in zip(highs, highs[1:])):
    raise SystemExit('Original 128-row power-of-two lookup highs differ from independent arithmetic')
positive = instruction_inventory(data, parent, modules)
identified = [r for r in positive['known_inline_data'] if r['module'] == 'com.apple.kec.Libm']
if len(identified) != 6:
    raise SystemExit('Actual-image positive must identify exactly six original math pools')
controls = []
for start, end in ranges:
    for offset in (start, end - 1):
        changed = bytearray(data)
        changed[at + offset] ^= 1
        try:
            instruction_inventory(changed, parent, modules)
        except ValueError as error:
            if 'External PC-relative encoding' not in str(error):
                raise
            controls.append(dict(offset=offset, refusal=str(error)))
        else:
            raise SystemExit('A modified known pool must not be excluded by its prefix')
changed = bytearray(data)
struct.pack_into('<I', changed, at + 4, 0x15ffffff)
try:
    instruction_inventory(changed, parent, modules)
except ValueError as error:
    controls.append(dict(offset=4, refusal=str(error)))
else:
    raise SystemExit('An unrelated external code branch must still be refused')
report = dict(original_sha256=expected, pools=records, power_lookup_rows=128, power_lookup_max_ulps=max_ulps,
              controls=controls, pc_relative_encodings_preserved=positive['pc_relative_encodings_preserved'],
              original_files_modified=False, static_only=True, runtime_qualified=False)
(ROOT / 'build/display-analysis/libm-inline-audit.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: six complete original math pools, real literal references/boundaries, 128 independent lookup rows and 13 refusal controls')
