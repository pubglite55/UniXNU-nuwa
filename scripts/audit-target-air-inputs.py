#!/usr/bin/env python3
"""Audit exact original UI AIR inputs; decode only, never compile/execute a GPU shader."""
import concurrent.futures
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / '.cache/firmware/target-volumes/os-mount/System/Library'
OUT = ROOT / 'build/gpu-analysis/air'
LLVM_ROOT = Path('/opt/homebrew/opt/llvm')
LLVM_DIS = LLVM_ROOT / 'bin/llvm-dis'
PINS = {
    'Frameworks/QuartzCore.framework/default.metallib':
        '606f913adf520420f9b4bb666efb782a68c830f082f1e559e17b20d0d13adbc9',
    'PrivateFrameworks/RenderBox.framework/default.metallib':
        'd76883f626b1527c36fb0940cf27dcade503a55cf2fa05c8f7a247a40ccebec4',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def extent(data, start, length):
    require(0 <= start <= len(data) and 0 <= length <= len(data) - start, 'Original input extent outside file')
    return data[start:start + length]


def slices(data):
    if data[:4] != b'\xca\xfe\xba\xbe':
        return [(dict(offset=0, bytes=len(data)), data)]
    n, = struct.unpack_from('>I', data, 4)
    require(n == 2, 'Exact target QuartzCore has two bounded universal slices')
    records = []
    for i in range(n):
        cpu, subtype, offset, size, alignment = struct.unpack('>5I', extent(data, 8 + 20 * i, 20))
        require(offset >= 8 + 20 * n and alignment <= 16 and not offset % (1 << alignment), 'Bounded original universal slice alignment')
        records.append((dict(cpu=hex(cpu), subtype=hex(subtype), offset=offset, bytes=size), extent(data, offset, size)))
    require(records[0][0]['offset'] + records[0][0]['bytes'] <= records[1][0]['offset'], 'Disjoint original universal slices')
    return records


def entries(data):
    require(data[:16] == bytes.fromhex('4d544c42010002000700008211000700') and
            struct.unpack_from('<Q', data, 16)[0] == len(data), 'Exact target MTLB header profile')
    sections = [tuple(pair) for pair in struct.iter_unpack('<2Q', extent(data, 24, 64))]
    for at, size in sections:
        extent(data, at, size)
    for (at, size), (next_at, _) in zip(sections, sections[1:]):
        require(88 <= at <= at + size <= next_at, 'Disjoint ordered original MTLB sections')
    at, length = sections[0]
    count, = struct.unpack('<I', extent(data, at, 4))
    require(0 < count <= 4096, 'Bounded nonempty original UI function inventory')
    cursor, records = at + 4, []
    for index in range(count):
        record_size, = struct.unpack('<I', extent(data, cursor, 4))
        require(8 <= record_size <= at + 4 + length - cursor, 'Bounded original function record')
        end, tag_at = cursor + record_size, cursor + 4
        tags = {}
        while tag_at < end:
            tag = extent(data, tag_at, 4)
            tag_at += 4
            if tag == b'ENDT':
                require(tag_at == end, 'Exact original record terminator')
                break
            n, = struct.unpack('<H', extent(data, tag_at, 2))
            tag_at += 2
            require(tag not in tags and tag_at + n <= end, 'Bounded unique original record tag')
            tags[tag] = extent(data, tag_at, n)
            tag_at += n
        require(tag == b'ENDT' and all(t in tags for t in (b'NAME', b'TYPE', b'HASH', b'OFFT', b'MDSZ')), 'Original AIR record fields')
        name = tags[b'NAME']
        require(name.endswith(b'\0') and b'\0' not in name[:-1] and len(tags[b'TYPE']) == 1 and len(tags[b'HASH']) == 32,
                'Exact original function name/type/hash field sizes')
        public, private, bitcode = struct.unpack('<3Q', tags[b'OFFT'])
        size, = struct.unpack('<Q', tags[b'MDSZ'])
        require(public < sections[1][1] and private < sections[2][1] and
                20 <= size <= sections[3][1] - bitcode and 0 <= bitcode < sections[3][1], 'Bounded original metadata/module offsets')
        wrapper = extent(data, sections[3][0] + bitcode, size)
        require(hashlib.sha256(wrapper).digest() == tags[b'HASH'], 'Original complete module HASH tag must match its bytes')
        magic, version, offset, bc_size, cpu = struct.unpack_from('<5I', wrapper)
        require(magic == 0x0b17c0de and version == 0 and offset >= 20 and bc_size > 4 and cpu == 0xffffffff,
                'Supported original LLVM bitcode wrapper')
        bc = extent(wrapper, offset, bc_size)
        require(bc[:4] == b'BC\xc0\xde', 'Actual LLVM bitcode signature, not a coincidental text string')
        records.append(dict(index=index, name=name[:-1].decode('ascii'), type=tags[b'TYPE'][0],
                            module_offset=bitcode, module_bytes=size, wrapper_sha256=tags[b'HASH'].hex(),
                            bitcode_sha256=hashlib.sha256(bc).hexdigest(), bitcode=bc))
        cursor = end
    require(cursor == at + 4 + length and cursor + 48 == sections[1][0],
            'Exact original function bytes: declared size excludes the four-byte record count')
    require(data[cursor:cursor + 6] == b'RLST\x10\x00' and data[cursor + 22:cursor + 28] == b'UUID\x10\x00' and
            data[cursor + 44:cursor + 48] == b'ENDT', 'Exact original reflection/UUID trailer profile')
    reflection, reflection_size = struct.unpack_from('<2Q', data, cursor + 6)
    require(reflection == sections[3][0] + sections[3][1] and reflection + reflection_size == len(data),
            'Original trailing reflection extent, not an unbounded bitcode scan')
    intervals = sorted(set((r['module_offset'], r['module_offset'] + r['module_bytes']) for r in records))
    require(all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])), 'Original module extents do not partially overlap')
    return records


OUT.mkdir(parents=True, exist_ok=True)
version = subprocess.check_output([LLVM_DIS, '--version'], text=True).strip()
require('LLVM version 23.1.3' in version, 'Qualify this audit with the actual inspected host LLVM version')
inputs, jobs = [], []
for file, expected in PINS.items():
    data = (BASE / file).read_bytes()
    require(hashlib.sha256(data).hexdigest() == expected, 'Exact unchanged target library: ' + file)
    library = Path(file).parent.stem
    views = slices(data)
    # The observed QuartzCore AIR-bearing slice is the first. Its classification
    # comes from real decoded triples, not assumptions about numeric CPU types.
    record, selected = views[0]
    modules = entries(selected)
    inputs.append(dict(file=file, sha256=expected, bytes=len(data), slices=[r for r, _ in views],
                       selected_slice=record, functions=len(modules)))
    for module in modules:
        module['library'] = library
        jobs.append(module)

# Verify the original triple in-process through LLVM's module API, without
# creating a target machine or overriding AIR with another architecture.
verifier_source = OUT / 'verify-air.c'
verifier_source.write_text(r'''#include <llvm-c/Analysis.h>
#include <llvm-c/BitReader.h>
#include <llvm-c/Core.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    LLVMMemoryBufferRef buffer = NULL;
    LLVMModuleRef module = NULL;
    char *message = NULL;
    LLVMContextRef context = LLVMContextCreate();
    int status = 1;
    if (LLVMCreateMemoryBufferWithContentsOfFile(argv[1], &buffer, &message)) goto done;
    if (LLVMParseBitcodeInContext2(context, buffer, &module)) goto done;
    if (strcmp(LLVMGetTarget(module), "air64-apple-ios17.7.0")) goto done;
    if (LLVMVerifyModule(module, LLVMReturnStatusAction, &message)) goto done;
    if (strcmp(LLVMGetTarget(module), "air64-apple-ios17.7.0")) goto done;
    status = 0;
done:
    if (message) { fputs(message, stderr); LLVMDisposeMessage(message); }
    if (module) LLVMDisposeModule(module);
    if (buffer) LLVMDisposeMemoryBuffer(buffer);
    LLVMContextDispose(context);
    return status;
}
''')
verifier = OUT / 'verify-air'
subprocess.run(['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-I', LLVM_ROOT / 'include', verifier_source, '-L', LLVM_ROOT / 'lib',
                '-lLLVM', '-Wl,-rpath,' + str(LLVM_ROOT / 'lib'), '-o', verifier], check=True, timeout=30)

deadline = time.monotonic() + 60


def decode(module):
    require(time.monotonic() < deadline, 'Bounded whole-library decoding deadline')
    bc = module.pop('bitcode')
    prefix = OUT / module['library'] / ('module-' + str(module['index']))
    prefix.parent.mkdir(parents=True, exist_ok=True)
    prefix.with_suffix('.bc').write_bytes(bc)
    result = subprocess.run([LLVM_DIS, prefix.with_suffix('.bc'), '-o', prefix.with_suffix('.ll')],
                            text=True, capture_output=True, timeout=8)
    require(result.returncode == 0, 'Actual LLVM bitcode decoding failed: ' + module['library'] + '/' + module['name'] + ': ' + result.stderr[:200])
    verified = subprocess.run([verifier, prefix.with_suffix('.bc')], text=True, capture_output=True, timeout=8)
    require(verified.returncode == 0, 'LLVM original-triple module verification failed: ' + module['library'] + '/' + module['name'] + ': ' + verified.stderr[:200])
    text = prefix.with_suffix('.ll').read_text()
    triple = re.search(r'^target triple = "([^"]+)"$', text, re.M)
    require(triple and triple[1] == 'air64-apple-ios17.7.0', 'Actual original AIR target triple')
    stages = [stage for stage in ('vertex', 'fragment', 'kernel', 'visible') if re.search(r'^!air\.' + stage + r' = ', text, re.M)]
    require(len(stages) == 1, 'One actual original function-kind metadata record: ' + module['library'] + '/' + module['name'])
    # This target's TYPE interpretation is checked against decoded AIR metadata.
    require(module['type'] == {'vertex': 0, 'fragment': 1, 'kernel': 2, 'visible': 4}[stages[0]], 'Actual TYPE agrees with original AIR stage metadata')
    definitions = re.findall(r'^define .*?@(?:"([^"]+)"|([^\s(]+))\(', text, re.M)
    require(module['name'] in {a or b for a, b in definitions}, 'Original exported function is defined by its own decoded module')
    module.update(triple=triple[1], stage=stages[0], definitions=len(definitions), llvm_module_verified=True,
                  air_intrinsics=sorted(set(re.findall(r'@(?:"(air\.[^"]+)"|(air\.[^\s(]+))\(', text))))
    module['air_intrinsics'] = sorted({a or b for a, b in module['air_intrinsics']})
    return module


with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    modules = list(pool.map(decode, jobs))
report = dict(inputs=inputs, llvm_dis_version=version,
              llvm_dis_sha256=hashlib.sha256(LLVM_DIS.read_bytes()).hexdigest(),
              modules=modules, stages=dict(Counter(m['stage'] for m in modules)),
              intrinsics=sorted({n for m in modules for n in m['air_intrinsics']}),
              original_files_modified=False, host_bitcode_decode_only=True,
              llvm_original_triple_module_verification=True,
              llvm_library_sha256=hashlib.sha256((LLVM_ROOT / 'lib/libLLVM.dylib').read_bytes()).hexdigest(),
              apple_bundle_signature_runtime_acceptance_qualified=False,
              adreno_code_generated=False, shader_execution_qualified=False, metal_api_qualified=False)
(OUT / 'target-inputs.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS:', len(modules), 'original UI AIR modules decoded/verified with real triples/function-kind/export metadata and complete module hashes')
print('Stages:', report['stages'], '; distinct AIR intrinsics:', len(report['intrinsics']))
print('Host input qualification only: no Adreno shader generation/execution, Metal API or UI qualification')
