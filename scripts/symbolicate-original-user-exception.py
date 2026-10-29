#!/usr/bin/env python3
"""Locate actual saved user PCs in the unchanged target's cache and local symbols."""
import argparse
import json
import mmap
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--report', required=True, type=Path)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
d = json.loads(args.report.read_text())
if d['stop_symbol'] != '_exception_triage' or d['bounded_timeout_interrupted']:
    raise SystemExit('Require a real exception entry, not a timeout or kernel panic')
states = d['entry_user_state_candidates']
if len(states) != 1:
    raise SystemExit('Require exactly one ABI-qualified saved user state')
u = states[0]
code = struct.unpack('<2Q', bytes.fromhex(d['entry_regions']['1:0:10']['bytes']))
if (int(d['observed_function_entry_arguments'][0], 16) != 6 or code != (1, int(u['user_pc'], 16)) or
        int(u['cpsr'], 16) & 31 or int(u['esr'], 16) >> 26 != 0x3c or
        bytes.fromhex(u['instruction_bytes'])[:4] != bytes.fromhex('000020d4')):
    raise SystemExit('Require cross-qualified actual EL0 BRK exception/code/PC/syndrome')

source = ROOT / 'refer/dyld'
if subprocess.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], text=True).strip() != 'a571176e8e00c47e95b95e3156820ebec0cbd5e6':
    raise SystemExit('Unexpected pinned cache-format reference')
work = ROOT / 'build/native-user-exception'
work.mkdir(parents=True, exist_ok=True)
cpp = work / 'offsets.cpp'
cpp.write_text('''#include <cstddef>
#include <cstdio>
#include "dyld_cache_format.h"
int main(){printf("%zu %zu %zu %zu %zu %zu %zu %zu %zu %zu\\n",
offsetof(dyld_cache_header,imagesTextOffset),offsetof(dyld_cache_header,localSymbolsOffset),
offsetof(dyld_cache_header,sharedRegionStart),sizeof(dyld_cache_image_text_info),
sizeof(dyld_cache_local_symbols_info),sizeof(dyld_cache_local_symbols_entry_64),
sizeof(dyld_cache_local_symbols_entry),offsetof(dyld_cache_header,symbolFileUUID),
offsetof(dyld_cache_header,mappingWithSlideOffset),sizeof(dyld_cache_mapping_and_slide_info));}
''')
subprocess.run(['xcrun', 'clang++', '-std=c++17', '-I', source / 'cache-builder', cpp, '-o', work / 'offsets'], check=True)
textoff, localoff, regionoff, textsize, infosize, entrysize, _, uuidfield, slidefield, slidesize = map(
    int, subprocess.check_output([work / 'offsets'], text=True).split())
if (textsize, infosize, entrysize) != (32, 24, 16):
    raise SystemExit('Unexpected original cache ABI')
cache = ROOT / '.cache/firmware/target-volumes/systemos-mount/System/Library/Caches/com.apple.dyld'
needle = bytes.fromhex(u['instruction_bytes'])
hits = []
catalog = []
for path in sorted(cache.glob('dyld_shared_cache_arm64*')):
    if path.suffix == '.symbols':
        continue
    with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as b:
        if b[:16].rstrip(b'\0') != b'dyld_v1   arm64':
            raise SystemExit('Unexpected original cache architecture')
        mo, mc = struct.unpack_from('<2I', b, 16)
        mappings = [struct.unpack_from('<3Q2I', b, mo + i * 32) for i in range(mc)]
        so, sc = struct.unpack_from('<2I', b, slidefield)
        for i in range(sc):
            catalog.append((path, struct.unpack_from('<7Q2I', b, so + i * slidesize)))
        pos = b.find(needle)
        while pos >= 0:
            for va, size, off, _, prot in mappings:
                if off <= pos and pos + len(needle) <= off + size and prot & 4:
                    hits.append(dict(file=path.name, offset=pos, unslid_pc=va + pos - off))
            pos = b.find(needle, pos + 1)
if len(hits) != 1:
    raise SystemExit('Actual instruction bytes must uniquely identify an executable cache mapping')
hit = hits[0]
slide = int(u['user_pc'], 16) - hit['unslid_pc']
b = (cache / 'dyld_shared_cache_arm64').read_bytes()
region, maximum = struct.unpack_from('<2Q', b, regionoff)[0], struct.unpack_from('<Q', b, regionoff + 16)[0]
if not 0 <= slide <= maximum or slide % 4096:
    raise SystemExit('Observed cache slide is outside the original cache bounds')
off, count = struct.unpack_from('<2Q', b, textoff)
images = []
for i in range(count):
    _, va, size, path = struct.unpack_from('<16sQ2I', b, off + i * textsize)
    images.append((va, size, b[path:b.find(b'\0', path)].decode()))
rows = []
with (cache / 'dyld_shared_cache_arm64.symbols').open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as symbols:
    if symbols[88:104] != b[uuidfield:uuidfield + 16]:
        raise SystemExit('Original symbols UUID does not match the original main cache')
    lo, _ = struct.unpack_from('<2Q', symbols, localoff)
    no, nc, so, ss, eo, ec = struct.unpack_from('<6I', symbols, lo)
    entries = {struct.unpack_from('<Q', symbols, lo + eo + i * entrysize)[0]:
               struct.unpack_from('<2I', symbols, lo + eo + i * entrysize + 8) for i in range(ec)}
    pcs = [int(u['user_pc'], 16)] + [int(f['lr'], 16) - 4 for f in u['frames'] if int(f['lr'], 16)]
    for pc in pcs:
        va = pc - slide
        image = next((im for im in images if im[0] <= va < im[0] + im[1]), None)
        row = dict(pc=hex(pc), unslid_va=hex(va), image=image[2] if image else None)
        if image and image[0] - region in entries:
            start, count = entries[image[0] - region]
            best = None
            if start + count > nc:
                raise SystemExit('Symbol entry exceeds the actual local table')
            for i in range(start, start + count):
                string, kind, section, _, value = struct.unpack_from('<IBBHQ', symbols, lo + no + i * 16)
                if not kind & 0xe0 and kind & 0xe == 0xe and section and image[0] <= value <= va and (best is None or value > best[0]):
                    best = value, string
            if best:
                value, string = best
                if string >= ss:
                    raise SystemExit('Invalid original symbol string offset')
                pos = lo + so + string
                row.update(nearest_local_symbol=symbols[pos:symbols.find(b'\0', pos)].decode(), offset=va - value)
        rows.append(row)
result = dict(kernel_sha256=d['kernel_sha256'], actual_exception='EXC_BREAKPOINT', actual_codes=list(code),
              unique_instruction_match=hit, cache_slide=hex(slide), frames=rows,
              local_symbols_uuid_matches=True, functional_ipados_ui_demonstrated=False,
              original_files_modified=False)

def read_original(va, length):
    for path, mapping in catalog:
        start, size, off = mapping[:3]
        if start <= va and va + length <= start + size:
            with path.open('rb') as stream:
                stream.seek(off + va - start)
                return stream.read(length), path, mapping
    raise SystemExit('Requested static address is not in an original cache mapping')

# Qualify the literal referenced by this observed original failure block;
# this is static disassembly evidence, not a captured runtime log message.
if rows[0].get('nearest_local_symbol') == '-[FBSDisplayMonitor _initWithBookendObserver:transformer:]':
    address = hit['unslid_pc'] - 0x48
    words = struct.unpack('<2I', read_original(address, 8)[0])
    adrp, add = words
    if adrp & 0x9f00001f != 0x90000002 or add & 0xffc003ff != 0x91000042:
        raise SystemExit('Original assertion reference instructions differ')
    immediate = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7ffff) << 2)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    literal = (address & ~4095) + (immediate << 12) + ((add >> 10) & 4095)
    raw, path, mapping = read_original(literal, 32)
    pointer, length = struct.unpack_from('<2Q', raw, 16)
    with path.open('rb') as stream:
        stream.seek(mapping[3])
        info = stream.read(40)
    if struct.unpack_from('<I', info)[0] != 2 or not 0 < length <= 256:
        raise SystemExit('Original assertion requires a bounded CFString and version-2 slide record')
    mask, base = struct.unpack_from('<2Q', info, 24)
    pointer = (pointer & (~mask & ((1 << 64) - 1))) + base
    text = read_original(pointer, length)[0].decode('ascii')
    result['static_original_assertion'] = dict(literal_va=hex(literal), text=text,
                                               runtime_string_captured=False)
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
