#!/usr/bin/env python3
"""Qualify original QuartzCore attribute/multi-buffer compiler paths offline."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--compiler', type=Path, required=True)
p.add_argument('--llvm-bindir', type=Path, required=True)
a = p.parse_args()
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'build/air-nir/resources'
OUT.mkdir(parents=True, exist_ok=True)
env = {k: v for k, v in os.environ.items() if not k.startswith(('IR3_', 'FD_MESA_', 'NIR_', 'MESA_SHADER_'))}
env['IR3_SHADER_DEBUG'] = 'asmroundtrip'
audit = json.loads((ROOT / 'build/gpu-analysis/air/target-inputs.json').read_text())
modules = {(m['library'], m['index']): m for m in audit['modules']}


def run(cmd, code=0):
    r = subprocess.run([str(x) for x in cmd], env=env, capture_output=True, text=True, timeout=20)
    if r.returncode != code:
        raise RuntimeError(f'Status {r.returncode}: {r.stderr[-2500:]}')
    return r.stdout


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


reports = []
for index in (7, 8, 9, 10, 11, 98):
    src = ROOT / f'build/gpu-analysis/air/QuartzCore/module-{index}.bc'
    if sha(src) != modules['QuartzCore', index]['bitcode_sha256']:
        raise RuntimeError('Original resource shader input differs')
    prefix = OUT / f'QuartzCore-{index}'
    run([a.compiler, src, '0x43050a01', prefix, '--compile'])
    interface = json.loads(prefix.with_suffix('.interface.json').read_text())
    attributes = [i for i in interface['inputs'] if i['kind'] == 'air.vertex_input']
    buffers = [i for i in interface['inputs'] if i['kind'] == 'air.buffer']
    wanted_attrs = [(0,4), (1,2), (2,2)] if index in (11,98) else [(0,4),(1,2),(3,4)]
    wanted_buffers = [(2,64),(3,16),(5,8)] if index == 8 else [(2,64),(3,32 if index in (11,98) else 16)]
    if [(i['index'],i['components']) for i in attributes] != wanted_attrs or [(i['index'],i['minimum_bytes']) for i in buffers] != wanted_buffers:
        raise RuntimeError('Resource interface differs from independently audited original metadata/accesses')
    if interface['runtime_resource_layout_qualified']:
        raise RuntimeError('Host schema cannot qualify runtime resource layouts')
    rng = random.Random(20261020 + index)
    cases = []
    for case in range(4096):
        attrs = struct.pack('<64f', *(rng.uniform(-4,4) + slot * 0.25 for slot in range(64)))
        blocks = [struct.pack('<' + 'f'*(i['minimum_bytes']//4), *(rng.uniform(0.25,2) for _ in range(i['minimum_bytes']//4))) for i in buffers]
        cases.append((case, attrs, blocks))
    inputs = prefix.with_suffix('.cases')
    inputs.write_bytes(b''.join(struct.pack('<I',v) + attrs + b''.join(blocks) for v,attrs,blocks in cases))
    meta = json.loads(run([a.compiler,src,'0x43050a01',prefix,'--compile','--test-resources',inputs]))
    oracle_bc, oracle_dylib = Path(str(prefix)+'.oracle.bc'), Path(str(prefix)+'.dylib')
    run([a.compiler,src,'0x43050a01',oracle_bc,'--test-resource-oracle'])
    run([a.llvm_bindir/'clang','-dynamiclib','-O0','-ffp-contract=off',oracle_bc,'-o',oracle_dylib])
    lib = ctypes.CDLL(str(oracle_dylib))
    oracle = lib.air_test_resource_oracle
    oracle.argtypes = [ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_void_p]
    oracle.restype = None
    raw = prefix.with_suffix('.eval').read_bytes()
    stride = len(interface['outputs']) * 16
    if len(raw) != len(cases)*stride:
        raise RuntimeError('Resource numerical output framing')
    for case,(vertex,attrs,blocks) in enumerate(cases):
        input_attrs = ctypes.create_string_buffer(attrs)
        backing = []
        pointers = (ctypes.c_void_p * 16)()
        for item,data in zip(buffers,blocks):
            alignment = item['minimum_alignment']
            block = ctypes.create_string_buffer(len(data)+alignment)
            address = (ctypes.addressof(block)+alignment-1) & ~(alignment-1)
            ctypes.memmove(address,data,len(data))
            pointers[item['index']] = address
            backing.append(block)
        expected = (ctypes.c_uint32 * 64)()
        oracle(input_attrs,pointers,vertex,expected)
        actual = struct.unpack_from('<'+'I'*(stride//4),raw,case*stride)
        for out in interface['outputs']:
            for component in range(out['components']):
                channel = out['slot']*4+component
                if actual[channel] != expected[channel]:
                    raise RuntimeError(f'Resource arithmetic mismatch: module {index}, case {case}, channel {channel}: {actual[channel]:08x} != {expected[channel]:08x}')
    reports.append(dict(library='QuartzCore',index=index,name=interface['function'],input_sha256=sha(src),
        numerical_cases=4096,exact_f32_equal=True,binary_bytes=meta['binary_bytes'],
        binary_sha256=sha(prefix.with_suffix('.bin')),interface=interface,asm_roundtrip=meta['asm_roundtrip'],gpu_executed=False))
    print(f'PASS: QuartzCore {index}: 4096 original-IR/NIR attribute and multi-buffer cases',flush=True)
# Original undefined output stays a refusal; do not fill a varying with zeros.
run([a.compiler,ROOT/'build/gpu-analysis/air/QuartzCore/module-6.bc','0x43050a01',OUT/'undefined-varying','--compile'],code=4)
# Actual incomplete test frames must refuse instead of reading zero-filled data.
short = OUT/'short.cases';short.write_bytes(b'\0'*8)
run([a.compiler,src,'0x43050a01',OUT/'short','--compile','--test-resources',short],code=4)
original = (ROOT/'build/gpu-analysis/air/QuartzCore/module-9.ll').read_text()
axis_source = (ROOT/'build/gpu-analysis/air/QuartzCore/module-8.ll').read_text()
mutations = {
    'attribute-overlap': original.replace('!"air.location_index", i32 1, i32 1','!"air.location_index", i32 0, i32 1',1),
    'attribute-too-large': original.replace('!"air.location_index", i32 1, i32 1','!"air.location_index", i32 16, i32 1',1),
    'buffer-write': original.replace('!"air.read"','!"air.write"'),
    'wrong-address-space': original.replace('!"air.address_space", i32 2','!"air.address_space", i32 1'),
    'explicit-buffer-too-short': axis_source.replace('!"air.buffer_size", i32 8','!"air.buffer_size", i32 4'),
    'missing-buffer-type': original.replace('!"air.arg_type_size"','!"air.unknown_type_size"'),
    'unused-contradiction': original.replace('!"air.vertex_input",','!"air.vertex_input", !"air.arg_unused",'),
    'buffer-binding-overlap': original.replace('!"air.buffer_size", i32 16, !"air.location_index", i32 3','!"air.buffer_size", i32 16, !"air.location_index", i32 2'),
}
for name,text in mutations.items():
    if text in (original,axis_source): raise RuntimeError('Resource mutation did not change input')
    ll,bc,prefix=OUT/(name+'.ll'),OUT/(name+'.bc'),OUT/name
    ll.write_text(text); run([a.llvm_bindir/'llvm-as',ll,'-o',bc])
    prefix.with_suffix('.bin').unlink(missing_ok=True)
    run([a.compiler,bc,'0x43050a01',prefix,'--compile'],code=4)
    if prefix.with_suffix('.bin').exists(): raise RuntimeError('Resource refusal exported code')
(OUT/'report.json').write_text(json.dumps(dict(originals=reports,undefined_output_refused=True,
    truncated_resource_case_refused=True,metadata_refusals=list(mutations),
    oracle_policy='Original IR host copy with fast rewrite permissions cleared to select the frontend separate-rounding evaluation',
    generated_isa_executed=False),indent=2)+'\n')
