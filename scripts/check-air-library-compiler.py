#!/usr/bin/env python3
"""Compile directly from unchanged target metallibs and test entry/integrity refusals."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'build/air-library/compiler'
OUT.mkdir(parents=True,exist_ok=True);exe=ROOT/'build/mesa-ir3/src/freedreno/ir3/air_nir'
manifest=json.loads((ROOT/'scripts/data/native-air-diagnostic-inputs.json').read_text());audit=json.loads((ROOT/'build/gpu-analysis/air/target-inputs.json').read_text())
paths={Path(x['file']).parent.stem:ROOT/'.cache/firmware/target-volumes/os-mount/System/Library'/x['file'] for x in audit['inputs']}
env={k:v for k,v in os.environ.items() if not k.startswith(('IR3_','FD_MESA_','NIR_','MESA_SHADER_'))};env['IR3_SHADER_DEBUG']='asmroundtrip'
def run(path,index,prefix,expected=0):
 p=subprocess.run([str(exe),str(path),manifest['chip_id'],str(prefix),'--compile-library',str(index)],capture_output=True,text=True,env=env,timeout=15)
 if p.returncode!=expected:raise SystemExit(f'Unexpected compiler result {p.returncode}: '+p.stderr[-2000:])
 if expected and prefix.with_suffix('.bin').exists():raise SystemExit('Refused library exported GPU code')
 return p
reports=[]
for case in manifest['cases']:
 prefix=OUT/case['name'];p=run(paths[case['library']],case['index'],prefix)
 for suffix,key in (('.bin','binary_sha256'),('.ir3.json','abi_sha256'),('.interface.json','interface_sha256')):
  if hashlib.sha256(prefix.with_suffix(suffix).read_bytes()).hexdigest()!=case[key]:raise SystemExit('Direct library compilation changed '+case['name']+suffix)
 meta=json.loads(p.stdout.strip().splitlines()[-1])
 if not meta['asm_roundtrip'] or meta['gpu_executed']:raise SystemExit('Actual compiler/assembler evidence required')
 reports.append(dict(name=case['name'],binary_sha256=case['binary_sha256'],complete_abi_and_interface_exact=True))
 print('PASS:',case['name'],'direct unchanged metallib -> exact A740 binary/ABI/interface',flush=True)
# Independent bounded record walk obtains the exact original NAME/TYPE/HASH
# fields. Metadata contradictions must fail after container hash validation.
raw=paths['QuartzCore'].read_bytes();slice_offset=struct.unpack_from('>I',raw,16)[0];start=struct.unpack_from('<Q',raw,slice_offset+24)[0];cursor=slice_offset+start+4
fields={}
for index in range(112):
 size=struct.unpack_from('<I',raw,cursor)[0];at=cursor+4;end=cursor+size;tags={}
 while at<end:
  tag=raw[at:at+4];at+=4
  if tag==b'ENDT':break
  n=struct.unpack_from('<H',raw,at)[0];at+=2;tags[tag]=(at,n);at+=n
 if index==111:fields=tags
 cursor=end
mutations={}
name=bytearray(raw);name[fields[b'NAME'][0]]^=1;mutations['entry-name']=name
stage=bytearray(raw);stage[fields[b'TYPE'][0]]=1;mutations['entry-stage']=stage
bad_hash=bytearray(raw);bad_hash[fields[b'HASH'][0]]^=1;mutations['module-hash']=bad_hash
for name,bytes_ in mutations.items():
 path=OUT/(name+'.metallib');path.write_bytes(bytes_);p=run(path,111,OUT/name,4)
 reason='library record contradicts actual AIR entry' if name!='module-hash' else 'library container status 4'
 if reason not in p.stderr:raise SystemExit('Wrong library refusal reason: '+p.stderr)
for value in ('-1','4096','99999999999999999999','1x',''):
 p=run(paths['QuartzCore'],value,OUT/('bad-index-'+str(len(value))),4)
 if 'library function index' not in p.stderr:raise SystemExit('Wrong index refusal')
run(paths['QuartzCore'],167,OUT/'outside-inventory',4)
p=run(paths['QuartzCore'],0,OUT/'unsupported-entry',4)
if 'globals or function-constant initialization unsupported' not in p.stderr:raise SystemExit('Existing unsupported AIR must remain refused')
for path in paths.values():
 original=next(x for x in audit['inputs'] if Path(x['file']).parent.stem==path.parent.stem)
 if hashlib.sha256(path.read_bytes()).hexdigest()!=original['sha256']:raise SystemExit('Original library changed')
(OUT/'report.json').write_text(json.dumps(dict(originals=reports,metadata_refusals=3,index_refusals=6,unsupported_air_refused=True,
    compiler_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),native_execution=False,gpu_execution=False),indent=2)+'\n')
print('PASS: direct metallib compile and actual entry-name/stage/hash/index/unsupported AIR refusals')
