#!/usr/bin/env python3
"""Qualify the unchanged target's actual Metal service/plugin discovery contract."""
import hashlib
import json
import mmap
from pathlib import Path
import plistlib
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import backed_offset, macho, unserialize_xml


def require(value, message):
    if not value:
        raise SystemExit(message)


directory = ROOT / '.cache/firmware/target-volumes/systemos-mount/System/Library/Caches/com.apple.dyld'
files, mappings, slides = [], [], []
for path in sorted(directory.glob('dyld_shared_cache_arm64*')):
    if path.suffix == '.symbols':
        continue
    stream = path.open('rb')
    data = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
    files.append((path.name, stream, data))
    require(data[:16].rstrip(b'\0') == b'dyld_v1   arm64', 'Require original ordinary ARM64 caches')
    at, count = struct.unpack_from('<2I', data, 16)
    for i in range(count):
        va, size, off, _, _ = struct.unpack_from('<3Q2I', data, at + 32 * i)
        mappings.append((va, va + size, off, data))
    at, count = struct.unpack_from('<2I', data, 312)
    for i in range(count):
        va, size, _, off, length, _, _, _ = struct.unpack_from('<6Q2I', data, at + 56 * i)
        if length:
            require(struct.unpack_from('<I', data, off)[0] == 2, 'Require the target v2 cache slide encoding')
            mask, base = struct.unpack_from('<2Q', data, off + 24)
            slides.append((va, va + size, mask, base))
main = files[0][2]
require(main[88:104].hex() == '590d839a82d230f1a17d0cc053420f73' and
        main[400:416].hex() == 'a1a859a2479c31998a34f4afbd808cf5', 'Exact target main/local-symbol UUIDs')


def read(va, size):
    for start, end, off, data in mappings:
        if start <= va and va + size <= end:
            return data[off + va - start:off + va - start + size]
    raise SystemExit('Unbacked target cache extent ' + hex(va))


def pointer(va):
    raw, = struct.unpack('<Q', read(va, 8))
    for start, end, mask, base in slides:
        if start <= va < end:
            payload = raw & (~mask & ((1 << 64) - 1))
            return payload + base if payload else 0
    return raw


def pair(pc, register):
    first, second = struct.unpack('<2I', read(pc, 8))
    require(first & 0x9f00001f == (0x90000000 | register) and
            second & 0xffc003ff == (0x91000000 | register << 5 | register), 'Require original ADRP/ADD pair')
    immediate = ((first >> 5) & 0x7ffff) << 2 | ((first >> 29) & 3)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    return (pc & ~4095) + (immediate << 12) + ((second >> 10) & 4095)


def branch(pc, linked=True):
    word, = struct.unpack('<I', read(pc, 4))
    require(word & 0xfc000000 == (0x94000000 if linked else 0x14000000), 'Require original direct branch')
    immediate = word & 0x3ffffff
    if immediate & (1 << 25):
        immediate -= 1 << 26
    return pc + (immediate << 2)


def resolved_call(pc):
    target = branch(pc)
    if struct.unpack('<I', read(target + 8, 4))[0] == 0xd61f0200:
        return pair(target, 16)
    return target


def cfstring(va):
    flags, = struct.unpack('<Q', read(va + 8, 8))
    length, = struct.unpack('<Q', read(va + 24, 8))
    require(flags == 1992 and 0 < length <= 512, 'Require original bounded ASCII constant CFString')
    return read(pointer(va + 16), length).decode('ascii')


region, = struct.unpack_from('<Q', main, 224)
at, count = struct.unpack_from('<2Q', main, 136)
images = {}
for i in range(count):
    uuid, va, _, name = struct.unpack_from('<16sQ2I', main, at + 32 * i)
    title = main[name:main.find(b'\0', name)].decode()
    if title.endswith(('/Metal.framework/Metal', '/IOGPU.framework/IOGPU', '/IOKit.framework/Versions/A/IOKit', '/AGXMetalA10.bundle/AGXMetalA10')):
        header = read(va, 32)
        size, = struct.unpack_from('<I', header, 20)
        blob = header + read(va + 32, size)
        image = macho(blob)
        actual_uuid = next(blob[pos + 8:pos + 24] for cmd, pos, _ in image['commands'] if cmd == 0x1b)
        require(actual_uuid == uuid, 'Actual Mach-O UUID must match the cache image record')
        images[va - region] = dict(name=title, va=va, uuid=uuid.hex())
require(len(images) == 4, 'Require exactly the target Metal, IOGPU, IOKit and AGXMetalA10 images')
symbols = {}
with (directory / 'dyld_shared_cache_arm64.symbols').open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
    require(data[88:104] == main[400:416], 'Local symbols must belong to this exact target cache')
    local, _ = struct.unpack_from('<2Q', data, 72)
    no, _, so, _, eo, count = struct.unpack_from('<6I', data, local)
    for i in range(count):
        image, start, n = struct.unpack_from('<Q2I', data, local + eo + 16 * i)
        if image not in images:
            continue
        for j in range(start, start + n):
            name, kind, section, _, value = struct.unpack_from('<IBBHQ', data, local + no + 16 * j)
            if not kind & 0xe0 and kind & 0xe == 0xe and section:
                text = data[local + so + name:data.find(b'\0', local + so + name)].decode()
                symbols.setdefault(text, []).append(value)



def uleb(data, at):
    value = shift = 0
    while at < len(data) and shift < 64:
        byte = data[at]
        at += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, at
        shift += 7
    raise SystemExit('Invalid original export-trie integer')


# Public exports need not occur in the local-symbols companion.
for entry in images.values():
    va = entry['va']
    size, = struct.unpack('<I', read(va + 20, 4))
    blob = read(va, 32 + size)
    image = macho(blob)
    link = next(segment for segment in image['segments'] if segment['name'] == '__LINKEDIT')
    export = None
    for command, position, _ in image['commands']:
        if command == 0x80000033:
            export = struct.unpack_from('<2I', blob, position + 8)
        elif command == 0x80000022:
            candidate = struct.unpack_from('<2I', blob, position + 40)
            if candidate[1]:
                export = candidate
    require(export and link['fileoff'] <= export[0] and
            export[0] + export[1] <= link['fileoff'] + link['filesize'], 'Original export trie must be LINKEDIT-backed')
    tree = read(link['va'] + export[0] - link['fileoff'], export[1])
    pending, visited = [(0, '')], set()
    while pending:
        at, prefix = pending.pop()
        require(at not in visited and len(visited) < 100000, 'Bounded noncyclic original export trie')
        visited.add(at)
        terminal, start = uleb(tree, at)
        require(start + terminal < len(tree), 'Bounded original export terminal')
        if terminal:
            flags, cursor = uleb(tree, start)
            if not flags & 8:  # Reexports do not define a local address.
                value, _ = uleb(tree, cursor)
                address = value if flags & 3 == 2 else va + value
                values = symbols.setdefault(prefix, [])
                if address not in values:
                    values.append(address)
        at = start + terminal
        children = tree[at]
        at += 1
        for _ in range(children):
            end = tree.index(0, at)
            label = tree[at:end].decode('ascii')
            child, at = uleb(tree, end + 1)
            pending.append((child, prefix + label))


def symbol(name):
    values = symbols.get(name, [])
    require(len(values) == 1, 'Require one original symbol: ' + name)
    return values[0]


register = symbol('_MTLRegisterDevices')
plugin = symbol('_getMetalPluginClassForService')
require(read(pair(register + 0x4c, 0), 16) == b'IOAcceleratorES\0' and
        resolved_call(register + 0x54) == symbol('_IOServiceMatching') and
        resolved_call(register + 0x64) == symbol('_IOServiceGetMatchingServices') and
        branch(register + 0xa8) == plugin and
        branch(register + 0xb8) in symbols['_objc_msgSend$initWithAcceleratorPort:'] and
        branch(register + 0xc4) == symbol('_MTLAddDevice') and
        read(register + 0xbc, 4) == bytes.fromhex('800000b4'), 'Actual service matching and plugin initialization chain')
properties = {offset: cfstring(pair(plugin + offset, register)) for offset, register in
              ((0x14, 1), (0x4c, 0), (0x5c, 2), (0x7c, 1))}
require(list(properties.values()) == ['MetalPluginName', '/System/Library/Extensions', '.bundle', 'MetalPluginClassName'] and
        resolved_call(plugin + 0x24) == resolved_call(plugin + 0x90) == symbol('_IORegistryEntryCreateCFProperty'), 'Actual original registry properties and bundle path')
require(branch(plugin + 0xb8) in symbols['_objc_msgSend$classNamed:'] and
        branch(plugin + 0xec) in symbols['_objc_msgSend$principalClass'] and
        branch(plugin + 0x108) in symbols['_objc_msgSend$isSubclassOfClass:'] and
        read(plugin + 0x110, 4) == bytes.fromhex('94129f9a'), 'Original named/principal class paths retain their real subclass acceptance check')
first, second = struct.unpack('<2I', read(plugin + 0xf4, 8))
require(first & 0x9f00001f == 0x90000008 and second & 0xffc003ff == 0xf9400100,
        'Original subclass check loads its actual class reference')
immediate = ((first >> 5) & 0x7ffff) << 2 | ((first >> 29) & 3)
if immediate & (1 << 20):
    immediate -= 1 << 21
class_reference = ((plugin + 0xf4) & ~4095) + (immediate << 12) + ((second >> 10) & 4095) * 8
require(pointer(class_reference) == symbol('_OBJC_CLASS_$__MTLDevice'), 'Actual required subclass is _MTLDevice')
device = symbol('_IOGPUDeviceCreateWithAPIProperty')
require(resolved_call(device + 0x4c) == symbol('_IOServiceOpen') and
        read(device + 0x30, 12)[:8] == bytes.fromhex('28008052483c1033'), 'Original IOGPU open uses base type 1 and the supplied API value in its upper 16 bits')
wrapper = symbol('_IOGPUDeviceCreate')
require(read(wrapper, 8) == bytes.fromhex('010080d2020080d2') and branch(wrapper + 8, False) == device, 'Default IOGPU wrapper preserves null API-property / zero API value')

kernel = (ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed').read_bytes()
require(hashlib.sha256(kernel).hexdigest() == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7', 'Require unchanged original kernelcache')
segments = macho(kernel)['segments']
info = next(s for s in segments if s['name'] == '__PRELINK_INFO')
at = backed_offset(segments, info['va'], info['filesize'], len(kernel))
entries = {e['CFBundleIdentifier']: e for e in unserialize_xml(kernel[at:at + info['filesize']])['_PrelinkInfoDictionary']}
agx = entries['com.apple.AGXG9G']['IOKitPersonalities']['AGXG9G_A0']
require(agx['MetalPluginName'] == 'AGXMetalA10' and agx['IONameMatch'] == ['gpu,t8011'], 'Original Apple GPU personality identity, not an Adreno match')
plist = ROOT / '.cache/firmware/target-volumes/os-mount/System/Library/Extensions/AGXMetalA10.bundle/Info.plist'
bundle = plistlib.loads(plist.read_bytes())
require(bundle['CFBundleIdentifier'] == 'com.apple.AGXMetalA10' and bundle['CFBundleExecutable'] == 'AGXMetalA10' and
        bundle['NSPrincipalClass'] == 'AGXPrincipalDevice' and bundle['CFBundleVersion'] == '282.14', 'Original target plugin metadata')
out = ROOT / 'build/gpu-analysis'
out.mkdir(parents=True, exist_ok=True)
(out / 'metal-discovery.json').write_text(json.dumps(dict(
    cache_uuid=main[88:104].hex(), local_symbols_uuid=main[400:416].hex(), images=list(images.values()),
    service_match='IOAcceleratorES', plugin_properties=list(properties.values()),
    plugin_info_sha256=hashlib.sha256(plist.read_bytes()).hexdigest(), original_principal_class=bundle['NSPrincipalClass'],
    functions={name: dict(va=hex(va), inspected_bytes=n, sha256=hashlib.sha256(read(va, n)).hexdigest())
               for name, va, n in [('register', register, 0xf0), ('plugin', plugin, 0x130), ('iogpu_open', device, 0x78)]},
    iogpu_base_open_type=1, iogpu_api_shift=16, native_metal_plugin_required=True,
    static_only=True, runtime_device_created=False, original_instructions_modified=False,
    original_principal_class_runtime_acceptance_qualified=False, adreno_metal_qualified=False), indent=2) + '\n')
print('PASS: actual target IOAcceleratorES matching, Metal bundle/property/class checks and IOGPU open-type contract')
print('Static discovery evidence only: no native Adreno Metal plugin, runtime device or GPU execution is qualified')
