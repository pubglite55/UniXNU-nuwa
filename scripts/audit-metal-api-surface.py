#!/usr/bin/env python3
"""Which Metal API does the unchanged target's graphics stack actually send? (static, read-only)

The native Adreno Metal plugin has to supply a real _MTLDevice and the objects hanging off it. How much of Metal that means depends
on the clients, so this measures it: the selectors declared by the Metal protocols (from the iPhoneOS SDK headers, via the clang AST)
against the selector references (__objc_selrefs) of the compositor and its neighbours in the target's unchanged dyld shared cache.
A selector reference proves the image can send that message, not that it does on the paths the system UI takes; the list is an upper
bound of the surface that compositing needs and a lower bound of what any client may call.

Output: build/gpu-analysis/metal-api-surface.json (ignored) and a summary on stdout. The SDK is newer than iPadOS 17.7.11; selectors the
SDK declares but the target never references simply do not appear, and selectors only the target knows are listed as 'unmatched'."""
import json
import mmap
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import macho

PROTOCOLS = ['MTLDevice', 'MTLCommandQueue', 'MTLCommandBuffer', 'MTLCommandEncoder', 'MTLRenderCommandEncoder',
             'MTLBlitCommandEncoder', 'MTLComputeCommandEncoder', 'MTLParallelRenderCommandEncoder', 'MTLResource', 'MTLTexture',
             'MTLBuffer', 'MTLLibrary', 'MTLFunction', 'MTLRenderPipelineState', 'MTLComputePipelineState', 'MTLSamplerState',
             'MTLDepthStencilState', 'MTLEvent', 'MTLSharedEvent', 'MTLFence', 'MTLHeap', 'MTLDrawable', 'MTLCaptureScope',
             'MTLArgumentEncoder', 'MTLIndirectCommandBuffer', 'MTLCounterSampleBuffer', 'MTLBinaryArchive']
IMAGES = ['/System/Library/Frameworks/QuartzCore.framework/QuartzCore', '/System/Library/Frameworks/Metal.framework/Metal',
          '/System/Library/Frameworks/MetalKit.framework/MetalKit', '/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore',
          '/System/Library/Frameworks/CoreImage.framework/CoreImage', '/System/Library/PrivateFrameworks/IOMobileFramebuffer.framework/IOMobileFramebuffer']


def sdk_selectors():
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
    result = {}
    with tempfile.TemporaryDirectory() as td:
        source = Path(td) / 'm.m'
        source.write_text('#import <Metal/Metal.h>\n#import <QuartzCore/CAMetalLayer.h>\n')
        for name in PROTOCOLS:
            out = subprocess.run(['xcrun', 'clang', '-fsyntax-only', '-fobjc-arc', '-isysroot', sdk, '-target', 'arm64-apple-ios17.0',
                                  '-Xclang', '-ast-dump=json', '-Xclang', '-ast-dump-filter', '-Xclang', name, str(source)],
                                 capture_output=True, text=True).stdout
            selectors = set()
            decoder, at = json.JSONDecoder(), 0
            while True:
                at = out.find('{', at)
                if at < 0:
                    break
                node, at = decoder.raw_decode(out, at)
                if node.get('kind') != 'ObjCProtocolDecl' or node.get('name') != name:
                    continue
                for child in node.get('inner', []):
                    if child.get('kind') == 'ObjCMethodDecl':
                        selectors.add(child['name'])
                    elif child.get('kind') == 'ObjCPropertyDecl':
                        prop = child['name']
                        selectors.add(prop)
                        if not child.get('readonly') and 'readonly' not in json.dumps(child.get('inner', [])):
                            selectors.add('set' + prop[0].upper() + prop[1:] + ':')
            result[name] = sorted(selectors)
    return result


def cache():
    directory = ROOT / '.cache/firmware/target-volumes/systemos-mount/System/Library/Caches/com.apple.dyld'
    files, mappings, slides = [], [], []
    for path in sorted(directory.glob('dyld_shared_cache_arm64*')):
        if path.suffix == '.symbols':
            continue
        stream = path.open('rb')
        data = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
        files.append((stream, data))
        if data[:16].rstrip(b'\0') != b'dyld_v1   arm64':
            raise SystemExit('Require the original ordinary ARM64 cache')
        at, count = struct.unpack_from('<2I', data, 16)
        for i in range(count):
            va, size, off, _, _ = struct.unpack_from('<3Q2I', data, at + 32 * i)
            mappings.append((va, va + size, off, data))
        at, count = struct.unpack_from('<2I', data, 312)
        for i in range(count):
            va, size, _, off, length, _, _, _ = struct.unpack_from('<6Q2I', data, at + 56 * i)
            if length:
                mask, base = struct.unpack_from('<2Q', data, off + 24)
                slides.append((va, va + size, mask, base))
    main = files[0][1]
    if main[88:104].hex() != '590d839a82d230f1a17d0cc053420f73':
        raise SystemExit('Not the exact target cache')

    def read(va, size):
        for start, end, off, data in mappings:
            if start <= va and va + size <= end:
                return data[off + va - start:off + va - start + size]
        raise SystemExit('Unbacked cache extent ' + hex(va))

    def pointer(va):
        raw, = struct.unpack('<Q', read(va, 8))
        for start, end, mask, base in slides:
            if start <= va < end:
                payload = raw & (~mask & ((1 << 64) - 1))
                return payload + base if payload else 0
        return raw

    def cstring(va):
        out = bytearray()
        while len(out) < 256:
            byte = read(va + len(out), 1)[0]
            if not byte:
                break
            out.append(byte)
        return out.decode('ascii', 'replace')

    return main, read, pointer, cstring


def main():
    protocols = sdk_selectors()
    declared = {s for sels in protocols.values() for s in sels}
    cache_main, read, pointer, cstring = cache()
    table, count = struct.unpack_from('<2Q', cache_main, 136)
    found = {}
    for i in range(count):
        _, va, _, name = struct.unpack_from('<16sQ2I', cache_main, table + 32 * i)
        title = cache_main[name:cache_main.find(b'\0', name)].decode()
        if title not in IMAGES:
            continue
        header = read(va, 32)
        size, = struct.unpack_from('<I', header, 20)
        image = macho(header + read(va + 32, size))
        selrefs = set()
        for segment in image['segments']:
            for section in segment['sections']:
                if section['name'] == '__objc_selrefs':
                    for at in range(section['va'], section['va'] + section['size'], 8):
                        target = pointer(at)
                        if target:
                            selrefs.add(cstring(target))
        found[title] = selrefs
    report = {'sdk_protocol_selectors': {k: len(v) for k, v in protocols.items()}, 'images': {}}
    for title, selrefs in found.items():
        used = {name: sorted(set(sels) & selrefs) for name, sels in protocols.items()}
        report['images'][title] = {'selector_references': len(selrefs), 'declared_and_referenced': {k: v for k, v in used.items() if v}}
        total = sorted({s for v in used.values() for s in v})
        report['images'][title]['distinct_declared_and_referenced'] = len(total)
        print('%-70s %6d selrefs, %4d Metal-protocol selectors referenced' % (title.split('/')[-1], len(selrefs), len(total)))
        for name, selectors in used.items():
            if selectors:
                print('   %-34s %3d of %3d' % (name, len(selectors), len(protocols[name])))
    quartz = found.get(IMAGES[0], set())
    mtl_like = sorted(s for s in quartz if re.match(r'^(new(Render|Compute|Texture|Buffer|Library|Sampler|Depth|Fence|Event|Shared|Heap)|setFragment|setVertex|setRenderPipeline|drawPrimitives|drawIndexedPrimitives|setViewport|setScissor|replaceRegion|getBytes|presentDrawable|commit|waitUntil|addCompletedHandler|addScheduledHandler|renderCommandEncoder|blitCommandEncoder|computeCommandEncoder|commandBuffer|endEncoding|copyFrom|generateMipmaps|setLabel|iosurface|registryID|supports)', s)
                     and s not in declared)
    report['quartzcore_metal_like_selectors_not_in_sdk_protocols'] = mtl_like
    out = ROOT / 'build/gpu-analysis'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'metal-api-surface.json').write_text(json.dumps(report, indent=1) + '\n')
    print('QuartzCore Metal-like selectors outside the SDK protocols (private SPI or other classes):', len(mtl_like))
    print('PASS: Metal API surface audit (static); written to build/gpu-analysis/metal-api-surface.json')


if __name__ == '__main__':
    main()
