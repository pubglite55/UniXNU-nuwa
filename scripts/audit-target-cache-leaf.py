#!/usr/bin/env python3
"""Locate the original cache's public getuid stub without rewriting any input."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / 'refer/dyld'
revision = subprocess.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], text=True).strip()
if revision != 'a571176e8e00c47e95b95e3156820ebec0cbd5e6':
    raise SystemExit('Expected the pinned Darwin 23 dyld format source')
out = ROOT / 'build/cache-leaf-host'
out.mkdir(parents=True, exist_ok=True)
unit = out / 'offsets.cpp'
unit.write_text('''#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <uuid/uuid.h>
#include "dyld_cache_format.h"
int main() { printf("%zu %zu\\n", offsetof(dyld_cache_header, imagesOffset), sizeof(dyld_cache_image_info)); }
''')
subprocess.run(['xcrun', 'clang++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-I',
                source / 'cache-builder', unit, '-o', out / 'offsets'], check=True)
images_field, image_size = map(int, subprocess.check_output([out / 'offsets'], text=True).split())
if image_size != 32:
    raise SystemExit('Unexpected original image table ABI')
directory = ROOT / '.cache/firmware/target-volumes/systemos-mount/System/Library/Caches/com.apple.dyld'
main = (directory / 'dyld_shared_cache_arm64').read_bytes()
audit = json.loads((ROOT / 'build/target-userspace/dyld-cache-audit.json').read_text())


def read(va, size):
    for row in audit['cache_files']:
        for mapping in row['mappings']:
            start = int(mapping['address'], 16)
            if start <= va and va + size <= start + mapping['size']:
                offset = mapping['fileoff'] + va - start
                with (directory / row['file']).open('rb') as stream:
                    stream.seek(offset)
                    data = stream.read(size)
                if len(data) != size:
                    raise SystemExit('Short original cache read')
                return data, row['file'], offset
    raise SystemExit('Address is outside actual target mappings')


at, count = struct.unpack_from('<II', main, images_field)
images = []
for index in range(count):
    address, _, _, path_offset, _ = struct.unpack_from('<3Q2I', main, at + index * image_size)
    name = main[path_offset:main.index(b'\0', path_offset)].decode()
    if name == '/usr/lib/system/libsystem_kernel.dylib':
        images.append(address)
if len(images) != 1:
    raise SystemExit('Expected exactly one original libsystem_kernel image')
image = images[0]
header, _, _ = read(image, 32)
magic, cpu, subtype, _, commands, command_bytes, _, _ = struct.unpack('<8I', header)
if (magic, cpu, subtype) != (0xfeedfacf, 0x100000c, 0):
    raise SystemExit('Use only the original ordinary-ARM64 target image')
load_commands, _, _ = read(image + 32, command_bytes)
at = 0
linkedit = trie_info = None
for _ in range(commands):
    cmd, size = struct.unpack_from('<II', load_commands, at)
    if cmd == 0x19:
        name, va, length, fileoff, filesize = struct.unpack_from('<16s4Q', load_commands, at + 8)
        if name.rstrip(b'\0') == b'__LINKEDIT':
            linkedit = (va, length, fileoff, filesize)
    elif cmd == 0x80000033:
        trie_info = struct.unpack_from('<II', load_commands, at + 8)
    at += size
if not linkedit or not trie_info or not linkedit[2] <= trie_info[0] < trie_info[0] + trie_info[1] <= linkedit[2] + linkedit[3]:
    raise SystemExit('Original export trie is outside LINKEDIT')
trie, _, _ = read(linkedit[0] + trie_info[0] - linkedit[2], trie_info[1])


def uleb(cursor):
    value = shift = 0
    while cursor < len(trie) and shift < 64:
        byte = trie[cursor]
        cursor += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, cursor
        shift += 7
    raise SystemExit('Invalid original export trie integer')


node, suffix = 0, '_getuid'
while True:
    terminal_size, cursor = uleb(node)
    end = cursor + terminal_size
    if not suffix:
        if not terminal_size:
            raise SystemExit('Original public getuid export is absent')
        flags, cursor = uleb(cursor)
        offset, cursor = uleb(cursor)
        if flags != 0 or cursor != end:
            raise SystemExit('Expected a plain regular original export')
        target = image + offset
        break
    children = trie[end]
    cursor = end + 1
    edges = []
    for _ in range(children):
        edge_end = trie.index(0, cursor)
        edge = trie[cursor:edge_end].decode()
        child, cursor = uleb(edge_end + 1)
        if suffix.startswith(edge):
            edges.append((edge, child))
    if len(edges) != 1:
        raise SystemExit('Original export trie path is absent or ambiguous')
    edge, node = edges[0]
    suffix = suffix[len(edge):]
code, filename, file_offset = read(target, 40)
words = struct.unpack('<10I', code)
# These are the original public wrapper's real success path, not injected code:
# mov x16,#24; svc #0x80; b.lo +28; ...; ret at +36.
if words[:3] != (0xd2800310, 0xd4001001, 0x540000e3) or words[9] != 0xd65f03c0 or file_offset % 4096 + 40 > 4096:
    raise SystemExit('The original getuid success path is not self-contained in one native page')
path = directory / filename
with path.open('rb') as stream:
    cache_header = stream.read(56)
    sig_offset, sig_size = struct.unpack_from('<QQ', cache_header, 40)
    stream.seek(sig_offset)
    signature = stream.read(sig_size)
    stream.seek(file_offset & ~4095)
    native_page = stream.read(4096)
code_directories = []
for index in range(struct.unpack_from('>I', signature, 8)[0]):
    _, offset = struct.unpack_from('>II', signature, 12 + index * 8)
    magic, length = struct.unpack_from('>II', signature, offset)
    if magic == 0xfade0c02:
        cd = signature[offset:offset + length]
        code_directories.append((hashlib.sha256(cd).digest()[:20].hex(), cd[39]))
expected = next(r for r in audit['cache_files'] if r['file'] == filename)['code_directories']
if len(code_directories) != 1 or code_directories != [(expected[0]['cdhash'], 14)]:
    raise SystemExit('Expected the actual unchanged 16K-signed original cache file')
digest = hashlib.sha256()
with path.open('rb') as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
report = dict(source_revision=revision, library='/usr/lib/system/libsystem_kernel.dylib',
              image_address=hex(image), public_export='_getuid', original_address=hex(target),
              file=filename, file_bytes=path.stat().st_size, file_sha256=digest.hexdigest(),
              file_offset=file_offset, native_page_offset=file_offset & ~4095,
              within_page_offset=file_offset & 4095, function_bytes=code.hex(),
              original_page_sha256=hashlib.sha256(native_page).hexdigest(),
              success_return_offset=36, syscall_number=24, signature_offset=sig_offset,
              signature_size=sig_size, original_cdhash=code_directories[0][0], signing_block_bytes=16384,
              original_input_modified=False, host_source_analysis_only=True, runtime_executed=False)
(out / 'getuid.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: actual public getuid export located in original 16K-signed cache; runtime still unqualified')
print(filename, hex(file_offset), digest.hexdigest())
