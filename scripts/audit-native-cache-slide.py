#!/usr/bin/env python3
"""Execute unchanged Darwin 23 rebasing logic on real target 4K data pages, on the host."""
import ctypes
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / 'refer/xnu'
revision = subprocess.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], text=True).strip()
if revision != 'd8b80295118ef25ac3a784134bcf95cd8e88109f':
    raise SystemExit('Expected the pinned Darwin 23 source')
out = ROOT / 'build/cache-slide-host'
out.mkdir(parents=True, exist_ok=True)
header = (source / 'osfmk/vm/vm_shared_region.h').read_text()
implementation = (source / 'osfmk/vm/vm_shared_region.c').read_text()
start = implementation.index('static kern_return_t\nrebase_chain_64(')
end = implementation.index('\nstatic kern_return_t\nrebase_chain(', start)
function = implementation[start:end]
working = (ROOT / '.cache/xnu-work/osfmk/vm/vm_shared_region.c').read_text()
working_start = working.index('static kern_return_t\nrebase_chain_64(')
working_end = working.index('\nstatic kern_return_t\nrebase_chain(', working_start)
if function != working[working_start:working_end]:
    raise SystemExit('The active source must retain the actual original rebase algorithm')
definition = re.search(r'struct vm_shared_region_slide_info_entry_v2 \{[\s\S]*?\n\};', header)[0]
granule = re.search(r'^#define PAGE_SIZE_FOR_SR_SLIDE\s+(\d+)$', header, re.M)[1]
if int(granule) != 4096:
    raise SystemExit('Unexpected source slide metadata granule')
prefix = ('#include <stdint.h>\n#include <string.h>\n#include <mach/kern_return.h>\n'
          '#define PAGE_SIZE_FOR_SR_SLIDE ' + granule + '\n' + definition + '\n'
          'typedef struct vm_shared_region_slide_info_entry_v2 *vm_shared_region_slide_info_entry_v2_t;\n')
bridge = '''
int probe_rebase(uint8_t *page, uint16_t start, uint32_t slide, void *info) {
  return rebase_chain_64(page, start, slide, info);
}
unsigned probe_header_size(void) { return sizeof(struct vm_shared_region_slide_info_entry_v2); }
'''
unit = out / 'original-rebase.c'
unit.write_text(prefix + function + bridge)
library = out / 'original-rebase.dylib'
subprocess.run(['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-dynamiclib',
                '-arch', 'arm64', unit, '-o', library], check=True)
native = ctypes.CDLL(str(library))
native.probe_rebase.argtypes = [ctypes.c_void_p, ctypes.c_uint16, ctypes.c_uint32, ctypes.c_void_p]
native.probe_rebase.restype = ctypes.c_int
if native.probe_header_size() != struct.calcsize('<6I2Q'):
    raise SystemExit('Compiled source metadata layout disagrees with actual encoded header')
audit = json.loads((ROOT / 'build/target-userspace/dyld-cache-audit.json').read_text())
directory = ROOT / '.cache/firmware/target-volumes/systemos-mount/System/Library/Caches/com.apple.dyld'
records = []
slide = 0x4000


def independent_chain(page, start, mask, value_add):
    shift = (mask & -mask).bit_length() - 1 - 2
    position = start
    delta = 1
    changes = 0
    while delta and position <= 4088:
        value = struct.unpack_from('<Q', page, position)[0]
        delta = (value & mask) >> shift
        value &= ~mask & ((1 << 64) - 1)
        if value:
            value = (value + value_add + slide) & ((1 << 64) - 1)
        struct.pack_into('<Q', page, position, value)
        position += delta
        changes += 1
    if position == 4092:
        value = struct.unpack_from('<I', page, position)[0]
        struct.pack_into('<I', page, position, (value + slide) & 0xffffffff)
        changes += 1
    elif position > 4088:
        raise SystemExit('Actual source chain would escape a native 4K page')
    return changes


for row in audit['cache_files']:
    for mapping in row['mappings']:
        if not mapping.get('slide_size'):
            continue
        with (directory / row['file']).open('rb') as stream:
            stream.seek(mapping['slide_offset'])
            metadata = stream.read(mapping['slide_size'])
            version, page_size, starts_at, starts_count, extras_at, extras_count, mask, value_add = struct.unpack_from('<6I2Q', metadata)
            if version != 2 or page_size != 4096 or starts_count * page_size != mapping['size'] or not mask >> 32:
                raise SystemExit('Target ordinary ARM64 data mapping is not native-4K v2 metadata')
            if starts_at + starts_count * 2 > len(metadata) or extras_at + extras_count * 2 > len(metadata):
                raise SystemExit('Actual slide tables exceed their declared bounds')
            starts = struct.unpack_from('<' + 'H' * starts_count, metadata, starts_at)
            extras = struct.unpack_from('<' + 'H' * extras_count, metadata, extras_at)
            active = [i for i, value in enumerate(starts) if value != 0x4000]
            samples = sorted({active[i * (len(active) - 1) // 7] for i in range(8)})
            info = ctypes.create_string_buffer(metadata)
            page_records = []
            for index in samples:
                stream.seek(mapping['fileoff'] + index * 4096)
                original = stream.read(4096)
                if len(original) != 4096:
                    raise SystemExit('Cannot read the exact original 4K data page')
                entry = starts[index]
                if entry & 0x8000:
                    chain_starts = []
                    extra_index = entry & 0x3fff
                    while True:
                        value = extras[extra_index]
                        chain_starts.append((value & 0x3fff) * 4)
                        extra_index += 1
                        if value & 0x8000:
                            break
                else:
                    chain_starts = [entry * 4]
                expected = bytearray(original)
                guarded = ctypes.create_string_buffer(b'G' * 32 + original + b'Z' * 32)
                changes = 0
                for chain in chain_starts:
                    changes += independent_chain(expected, chain, mask, value_add)
                    if native.probe_rebase(ctypes.addressof(guarded) + 32, chain, slide, info) != 0:
                        raise SystemExit('Original Darwin 23 rebasing rejected this actual target page')
                actual = guarded.raw[32:4128]
                if actual != expected or guarded.raw[:32] != b'G' * 32 or guarded.raw[4128:4160] != b'Z' * 32:
                    raise SystemExit('Original source result differs or writes outside its 4K page')
                if native.probe_rebase(ctypes.addressof(guarded) + 32, 4095, slide, info) != 5:
                    raise SystemExit('Original out-of-range chain refusal is not preserved')
                page_records.append(dict(index=index, chains=len(chain_starts), rebased_words=changes,
                                         original_sha256=hashlib.sha256(original).hexdigest(),
                                         result_sha256=hashlib.sha256(actual).hexdigest()))
            records.append(dict(file=row['file'], mapping_address=mapping['address'], mapping_bytes=mapping['size'],
                                slide_version=version, slide_page_bytes=page_size,
                                metadata_sha256=hashlib.sha256(metadata).hexdigest(),
                                sampled_pages=page_records))
if len(records) != 4 or sum(len(r['sampled_pages']) for r in records) != 32:
    raise SystemExit('Expected the four actual v2 mappings and 32 bounded real-page samples')
report = dict(source_revision=revision, source_function_sha256=hashlib.sha256(function.encode()).hexdigest(),
              compiled_library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
              host_execution_only=True, hardware_translation_inferred_from_host_test=False,
              original_source_algorithm_modified=False, metadata_or_cache_rewritten=False,
              slide_amount=slide, native_slide_granule=4096, actual_mappings=records,
              independent_results_match=True, page_guards_unchanged=True,
              out_of_range_chain_refused=True, qemu_shared_region_pager_observed=False,
              original_full_dyld_cache_loaded=False, hardware_tested=False)
(out / 'audit.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: unchanged Darwin 23 64-bit rebase logic matches 32 real target 4K pages across all four v2 slide mappings')
print('Host execution/source audit only: full cache-loader, QEMU pager faults and hardware still need qualification')
