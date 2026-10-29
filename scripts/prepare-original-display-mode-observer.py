#!/usr/bin/env python3
"""Bind a read-only original FBS mode-return observation to the actual cache/kernel."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct
import subprocess
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--metal-device',action='store_true');args=parser.parse_args()
address,length,digest,ret=(0x187ac8668,204,'8005e91f7637cf800246ae2130936f45cb57d6a0891a77c61f1f563e9b058d20',176) if args.metal_device else (0x19f3d0500,584,'ca4857e6617670f2369a0a6eb68be09e29135ce5dfda19ac1ea829229f0cc0ec',476)
subprocess.run(['python3',ROOT/'scripts/audit-target-display-query.py'],check=True)
plan=json.loads((ROOT/'build/display-analysis/query-plan.json').read_text())
cache=ROOT/'.cache/firmware/target-volumes/systemos-mount/System/Library/Caches/com.apple.dyld'
function=None
for file in sorted(cache.glob('dyld_shared_cache_arm64*')):
    if file.suffix=='.symbols':continue
    with file.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as data:
        at,count=struct.unpack_from('<2I',data,16)
        for index in range(count):
            va,size,offset,_,protection=struct.unpack_from('<3Q2I',data,at+index*32)
            if va<=address and address+length<=va+size:
                start=offset+address-va;function=data[start:start+length]
                if not protection&4 or hashlib.sha256(function).hexdigest()!=digest:
                    raise SystemExit('Original mode initializer/validation bytes differ')
if function is None or function[ret:ret+4]!=bytes.fromhex('c0035fd6'):
    raise SystemExit('Require the qualified original initializer return instruction')
plan.update(mode='user-return',query=address,query_prefix=function[:16].hex(),
    return_checkpoint=ret,object_bytes=0 if args.metal_device else 80,original_function_sha256=hashlib.sha256(function).hexdigest(),
    expected_process='backboardd' if args.metal_device else 'SpringBoard',purpose='Original default Metal device return' if args.metal_device else 'Original SpringBoard FBSDisplayMode validation and genuine returned object; read-only breakpoints')
if not args.metal_device:plan['original_mode_initializer_sha256']=hashlib.sha256(function).hexdigest()
for name in ('port_checkpoint','reply_checkpoint','main_display','displays','cas_request_id'):plan.pop(name,None)
(ROOT/('build/display-analysis/metal-device-return-plan.json' if args.metal_device else 'build/display-analysis/mode-plan.json')).write_text(json.dumps(plan,indent=2)+'\n')
print('PASS: exact original user function/RET and actual process/cache activation layout qualified')
