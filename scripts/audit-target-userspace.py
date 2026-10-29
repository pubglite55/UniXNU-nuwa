#!/usr/bin/env python3
"""Audit unchanged target launchd/dyld; this does not demonstrate userspace execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--volume', type=Path, default=ROOT / '.cache/firmware/target-volumes/os-mount')
args = parser.parse_args()
trustcache = ROOT / '.cache/firmware/target-volumes/static-trustcache.bin'
trust = trustcache.read_bytes()
version, trust_entries = struct.unpack_from('<I', trust)[0], struct.unpack_from('<I', trust, 20)[0]
if version != 2 or len(trust) != 24 + trust_entries * 24:
    raise SystemExit('Expected the original version-2 static trustcache')
results = []
for name, kind in [('sbin/launchd', 2), ('usr/lib/dyld', 7)]:
    data = (args.volume / name).read_bytes()
    magic, cpu, subtype, filetype, count, commands_size = struct.unpack_from('<6I', data)
    if (magic, cpu, subtype, filetype) != (0xfeedfacf, 0x100000c, 0, kind):
        raise SystemExit(f'{name}: requires ordinary ARM64 target Mach-O')
    offset = 32
    segments = []
    signature = None
    minimum = None
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, offset)
        if size < 8 or offset + size > 32 + commands_size:
            raise SystemExit('Invalid Mach-O load command')
        if command == 0x19:
            segname = data[offset + 8:offset + 24].split(b'\0')[0].decode()
            va, vmsize, fileoff, filesize = struct.unpack_from('<4Q', data, offset + 24)
            if (va % 4096 or vmsize % 4096 or fileoff % 4096
                    or fileoff + filesize > len(data) or filesize > vmsize):
                raise SystemExit(f'{name}: segment {segname} is not directly 4K mappable')
            segments.append({'name': segname, 'va': hex(va), 'vmsize': vmsize,
                             'fileoff': fileoff, 'filesize': filesize})
        elif command == 0x32:
            platform, minimum, sdk = struct.unpack_from('<3I', data, offset + 8)
            if platform != 2 or minimum >> 16 != 17:
                raise SystemExit('Unexpected target userspace platform/deployment')
        elif command == 0x1d:
            sigoff, sigsize = struct.unpack_from('<II', data, offset + 8)
            signature = data[sigoff:sigoff + sigsize]
        offset += size
    if minimum is None or signature is None:
        raise SystemExit('Target lacks build version or original code signature')
    smagic, slength, entries = struct.unpack_from('>3I', signature)
    if smagic != 0xfade0cc0 or slength > len(signature):
        raise SystemExit('Unexpected signature superblob')
    directories = []
    for index in range(entries):
        slot, start = struct.unpack_from('>2I', signature, 12 + index * 8)
        magic, length = struct.unpack_from('>2I', signature, start)
        if magic != 0xfade0c02:
            continue
        directory = signature[start:start + length]
        version, flags, hashoff, identoff, special, codeslots, limit = struct.unpack_from('>7I', directory, 8)
        hashsize, hashtype, platform, pageshift = struct.unpack_from('4B', directory, 36)
        if version >= 0x20300:
            limit64 = struct.unpack_from('>Q', directory, 56)[0]
            if limit64:
                limit = limit64
        if hashtype != 2 or hashsize != 32 or pageshift != 12 or limit > len(data):
            raise SystemExit('Expected the original target SHA-256 / 4K CodeDirectory')
        if codeslots != (limit + 4095) // 4096:
            raise SystemExit('Unexpected target code slot count')
        for page in range(codeslots):
            actual = hashlib.sha256(data[page * 4096:min((page + 1) * 4096, limit)]).digest()
            expected = directory[hashoff + page * hashsize:hashoff + (page + 1) * hashsize]
            if actual != expected:
                raise SystemExit(f'{name}: original code page {page} hash mismatch')
        cdhash = hashlib.sha256(directory).digest()[:20]
        matches = [i for i in range(trust_entries) if trust[24 + i * 24:44 + i * 24] == cdhash]
        if len(matches) != 1:
            raise SystemExit('Target CodeDirectory is absent or ambiguous in its original trustcache')
        directories.append({'slot': slot, 'original_static_trustcache_index': matches[0], 'identifier': directory[identoff:].split(b'\0')[0].decode(),
                            'flags': hex(flags), 'hash_page_bytes': 4096,
                            'code_slots_verified': codeslots, 'cdhash': hashlib.sha256(directory).hexdigest()[:40]})
    if not directories:
        raise SystemExit('No verified original CodeDirectory')
    results.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'arm64_subtype': 0,
                    'minimum_ios': f'{minimum >> 16}.{minimum >> 8 & 255}',
                    'segments_directly_4k_mappable': True, 'segments': segments,
                    'code_directories': directories})
report = {'target': 'iPad7,1 / 17.7.11 / 21H461', 'files': results,
          'code_page_hashes_verified': True, 'original_static_trustcache_sha256': hashlib.sha256(trust).hexdigest(), 'apple_trust_chain_verified': False,
          'native_4k_userspace_execution_observed': False, 'ipados_boot_demonstrated': False}
out = ROOT / 'build/target-userspace'
out.mkdir(parents=True, exist_ok=True)
(out / 'audit.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: unchanged target launchd/dyld ordinary ARM64, direct 4K segment layout and all original code-page hashes')
print('Apple trust-chain integration and actual userspace execution remain unverified')
