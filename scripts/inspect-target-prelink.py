#!/usr/bin/env python3
"""Inventory the supplied MH_EXECUTE cache and extract one kext's segments.

These remain prelinked bytes. This does not produce a relocated or loadable
standalone kext, and does not modify the supplied kernelcache.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bundle', default='com.apple.kec.corecrypto')
args = parser.parse_args()
source = ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed'
data = source.read_bytes()
assert hashlib.sha256(data).hexdigest() == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7'


def commands(at):
    magic, cpu, subtype, _, count, size = struct.unpack_from('<6I', data, at)
    assert (magic, cpu, subtype) == (0xfeedfacf, 0x100000c, 0)
    offset = at + 32
    for _ in range(count):
        command, length = struct.unpack_from('<II', data, offset)
        assert length >= 8 and offset + length <= at + 32 + size <= len(data)
        yield command, offset
        offset += length
    assert offset == at + 32 + size


def segments(at):
    result = []
    for command, offset in commands(at):
        if command == 0x19:
            name, va, size, fileoff, filesize = struct.unpack_from('<16s4Q', data, offset + 8)
            result.append({'name': name.rstrip(b'\0').decode(), 'va': va,
                           'size': size, 'fileoff': fileoff, 'filesize': filesize})
    return result


parent = segments(0)


def read_virtual(address, length):
    for segment in parent:
        if segment['va'] <= address and address + length <= segment['va'] + segment['filesize']:
            offset = segment['fileoff'] + address - segment['va']
            assert offset + length <= len(data)
            return data[offset:offset + length]
    raise ValueError(f'VA extent is not backed by cache bytes: {address:#x}+{length:#x}')


refs = {}


def unserialize(element):
    if 'IDREF' in element.attrib:
        return refs[element.attrib['IDREF']]
    tag = element.tag
    if tag == 'dict':
        children = list(element)
        assert len(children) % 2 == 0
        value = {unserialize(children[i]): unserialize(children[i + 1])
                 for i in range(0, len(children), 2)}
    elif tag == 'array':
        value = [unserialize(child) for child in element]
    elif tag == 'integer':
        value = int(element.text or '0', 0)
    elif tag in ('string', 'key'):
        value = element.text or ''
    elif tag == 'data':
        value = base64.b64decode(element.text or '')
    elif tag in ('true', 'false'):
        value = tag == 'true'
    else:
        raise ValueError(f'Unsupported OSUnserializeXML tag: {tag}')
    if 'ID' in element.attrib:
        refs[element.attrib['ID']] = value
    return value


info_segment = next(segment for segment in parent if segment['name'] == '__PRELINK_INFO')
xml = read_virtual(info_segment['va'], info_segment['filesize']).split(b'\0')[0]
prelink = unserialize(ET.fromstring(xml))
entries = prelink['_PrelinkInfoDictionary']
inventory = [{key: entry.get(key) for key in ['CFBundleIdentifier', 'CFBundleVersion',
             '_PrelinkExecutableLoadAddr', '_PrelinkExecutableSize', 'OSBundleLibraries']}
             for entry in entries]
output = ROOT / 'build/target-kexts'
output.mkdir(parents=True, exist_ok=True)
(output / 'inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
entry = next(entry for entry in entries if entry['CFBundleIdentifier'] == args.bundle)
address = entry['_PrelinkExecutableLoadAddr']
header_segment = next(segment for segment in parent
                      if segment['va'] <= address < segment['va'] + segment['filesize'])
header = header_segment['fileoff'] + address - header_segment['va']
destination = output / entry['CFBundleIdentifier']
destination.mkdir(exist_ok=True)
extracted = []
for segment in segments(header):
    if not segment['filesize']:
        continue
    blob = read_virtual(segment['va'], segment['filesize'])
    (destination / f'{segment["name"]}.bin').write_bytes(blob)
    extracted.append({**segment, 'sha256': hashlib.sha256(blob).hexdigest()})
# mach/kmod.h uses #pragma pack(4), including its 64-bit compatibility ABI.
kmod = read_virtual(entry['_PrelinkKmodInfo'], 196)
start, stop = struct.unpack_from('<QQ', kmod, 180)
assert any(segment['va'] <= start < segment['va'] + segment['filesize']
           for segment in extracted if segment['name'] == '__TEXT_EXEC')
report = {'bundle_id': entry['CFBundleIdentifier'], 'version': entry['CFBundleVersion'],
          'minimum_os': entry['MinimumOSVersion'], 'sdk': entry['DTSDKName'],
          'dependencies': entry['OSBundleLibraries'], 'segments': extracted,
          'kmod_start_va': hex(start), 'kmod_stop_va': hex(stop),
          'cpu_subtype': 0, 'relocated': False, 'loadable_standalone': False}
(destination / 'segments.json').write_text(json.dumps(report, indent=2) + '\n')
print(f'{len(entries)} target kext records; {args.bundle} {report["version"]}, ARM64 subtype 0')
print(f'{sum(segment["filesize"] for segment in extracted)} prelinked bytes; start {start:#x}')

metadata = {key: ({'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
                  if isinstance(value, bytes) else value) for key, value in entry.items()}
(destination / 'prelink-metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
relocations = prelink.get('_PrelinkLinkKASLROffsets')
if isinstance(relocations, bytes):
    (output / 'prelink-kaslr.bin').write_bytes(relocations)
    print(f'Exact cache-slide relocation metadata: {len(relocations)} bytes; entry keys: {list(entry)}')
