#!/usr/bin/env python3
"""Qualify unchanged QuartzCore fragment colors, sparse targets and MRT identity."""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--compiler', type=Path, required=True)
p.add_argument('--llvm-bindir', type=Path, required=True)
a=p.parse_args()
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'build/air-nir/fragments';OUT.mkdir(parents=True,exist_ok=True)
env=dict(os.environ,IR3_SHADER_DEBUG='asmroundtrip')

def run(cmd, status=0):
    r=subprocess.run([str(v) for v in cmd],env=env,capture_output=True,text=True,timeout=15)
    if r.returncode!=status:raise RuntimeError(f'Expected {status}, got {r.returncode}: {r.stderr[-1200:]}')
    return r

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def evaluate(src,prefix,expected_targets):
    # Evaluate exact original/module-copy IR and NIR independently; no rasterizer.
    interface=prefix.with_suffix('.interface.json');abi=prefix.with_suffix('.ir3.json')
    case=prefix.with_suffix('.cases');case.write_bytes(bytes(4+16*4*4))
    r=run([a.compiler,src,'0x43050a01',prefix,'--compile','--test-resources',case])
    if not json.loads(r.stdout)['asm_roundtrip']:raise RuntimeError('Missing actual encoding roundtrip')
    schema=json.loads(interface.read_text());device=json.loads(abi.read_text())
    if schema['stage']!='fragment' or schema['inputs'] or device['stage']!='fragment' or device['writes_position']:
        raise RuntimeError('Actual fragment stage/interface differs')
    if [(v['target'],v['components']) for v in schema['outputs']]!=expected_targets:
        raise RuntimeError('Logical output identity/width differs')
    # NIR store location must follow the source target, not the dense return index.
    nir=prefix.with_suffix('.nir').read_text();asm=prefix.with_suffix('.asm').read_text()
    for target,components in expected_targets:
        if f'FRAG_RESULT_DATA{target}' not in asm or f'VARYING_SLOT_POS' in nir:
            raise RuntimeError('Actual backend target mapping differs')
    actual={v['slot']:v for v in device['outputs']}
    if set(actual)!={4+target for target,_ in expected_targets}:
        raise RuntimeError('IR3 allocated output targets differ from source')
    for target,components in expected_targets:
        # IR3 allocated mask may contain only requested components.
        if actual[4+target]['register_id']==252:raise RuntimeError('No actual color output register')
    oracle=prefix.with_suffix('.oracle.bc')
    run([a.compiler,src,'0x43050a01',oracle,'--test-resource-oracle'])
    dylib=prefix.with_suffix('.dylib')
    run([a.llvm_bindir/'clang','-O2','-dynamiclib',oracle,'-o',dylib])
    lib=C.CDLL(str(dylib));fn=lib.air_test_resource_oracle
    fn.argtypes=[C.c_void_p,C.c_void_p,C.c_uint32,C.POINTER(C.c_float)]
    expected=(C.c_float*(len(expected_targets)*4))();fn(None,None,0,expected)
    if prefix.with_suffix('.eval').read_bytes()!=bytes(expected):raise RuntimeError('Original IR versus NIR bitwise color mismatch')
    return dict(binary_sha256=sha(prefix.with_suffix('.bin')),abi_sha256=sha(abi),binary_bytes=device['binary_bytes'],
                instructions=device['main_instructions'],targets=expected_targets,original_ir_nir_match=True,gpu_executed=False)

audit=json.loads((ROOT/'build/gpu-analysis/air/target-inputs.json').read_text())
originals=[]
for index,targets in [(69,[(2,1)]),(73,[(0,4),(1,4)]),(157,[(2,1)])]:
    src=ROOT/f'build/gpu-analysis/air/QuartzCore/module-{index}.bc'
    entry=next(v for v in audit['modules'] if v['library']=='QuartzCore' and v['index']==index)
    if sha(src)!=entry['bitcode_sha256']:raise RuntimeError('Supplied original input changed')
    result=evaluate(src,OUT/f'QuartzCore-{index}',targets)
    originals.append(dict(library='QuartzCore',index=index,source_sha256=sha(src),**result))
# Authored variants preserve target triple/version/options and mutate only ignored
# copies. They prevent all-zero original clears from hiding channel/target swaps.
scalar=(ROOT/'build/gpu-analysis/air/QuartzCore/module-69.ll').read_text()
mrt=(ROOT/'build/gpu-analysis/air/QuartzCore/module-73.ll').read_text()
synthetic=[]
for target in range(8):
    text=scalar.replace('ret <{ float }> zeroinitializer','ret <{ float }> <{ float -1.250000e+00 }>')
    text=text.replace('!"air.render_target", i32 2, i32 0','!"air.render_target", i32 '+str(target)+', i32 0')
    ll=OUT/f'target-{target}.ll';ll.write_text(text);bc=ll.with_suffix('.bc')
    run([a.llvm_bindir/'llvm-as',ll,'-o',bc]);synthetic.append(evaluate(bc,OUT/f'target-{target}',[(target,1)]))
text=mrt.replace('ret <{ <4 x float>, <4 x float> }> zeroinitializer',
    'ret <{ <4 x float>, <4 x float> }> <{ <4 x float> <float 1.000000e+00, float 2.000000e+00, float 3.000000e+00, float 4.000000e+00>, <4 x float> <float -4.000000e+00, float -3.000000e+00, float -2.000000e+00, float -1.000000e+00> }>')
ll=OUT/'mrt-distinct.ll';ll.write_text(text);bc=ll.with_suffix('.bc');run([a.llvm_bindir/'llvm-as',ll,'-o',bc])
synthetic.append(evaluate(bc,OUT/'mrt-distinct',[(0,4),(1,4)]))
mutations={
 'target-out-of-range':scalar.replace('!"air.render_target", i32 2, i32 0','!"air.render_target", i32 8, i32 0'),
 'dual-source':scalar.replace('!"air.render_target", i32 2, i32 0','!"air.render_target", i32 2, i32 1'),
 'duplicate-target':mrt.replace('!"air.render_target", i32 1, i32 0','!"air.render_target", i32 0, i32 0'),
 'depth-kind':scalar.replace('!"air.render_target"','!"air.depth"'),
 'undefined-scalar':scalar.replace('ret <{ float }> zeroinitializer','ret <{ float }> poison'),
 'undefined-vector':mrt.replace('ret <{ <4 x float>, <4 x float> }> zeroinitializer','ret <{ <4 x float>, <4 x float> }> poison'),
 'half-output':mrt.replace('float','half'),
 'mixed-stage':scalar.replace('!air.fragment = !{!15}','!air.fragment = !{!15}\n!air.vertex = !{!15}'),
 'missing-stage':scalar.replace('!air.fragment = !{!15}',''),
 'wrong-stage':scalar.replace('!air.fragment = !{!15}','!air.vertex = !{!15}'),
}
refusals=[]
for name,text in mutations.items():
    if text in (scalar,mrt):raise RuntimeError('No-op negative mutation')
    ll=OUT/(name+'.ll');ll.write_text(text);bc=ll.with_suffix('.bc');run([a.llvm_bindir/'llvm-as',ll,'-o',bc])
    r=run([a.compiler,bc,'0x43050a01',OUT/name,'--compile'],status=4)
    if not r.stderr.startswith('AIR refused:'):raise RuntimeError('Expected explicit frontend refusal')
    refusals.append(dict(name=name,reason=r.stderr.strip()))
(OUT/'report.json').write_text(json.dumps(dict(originals=originals,authored_color_controls=synthetic,
    refusal_controls=refusals,original_inventory_unchanged=True,actual_rasterization=False,
    fragment_interpolation=False,texture_sampling=False,metal_pipeline_linked=False),indent=2)+'\n')
print('PASS: three original scalar/MRT fragment shaders, all eight sparse targets and distinct MRT channels, actual roundtrip/IR3 targets and original-IR/NIR bits; ten refusals')
