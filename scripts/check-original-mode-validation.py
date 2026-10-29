#!/usr/bin/env python3
"""Qualify the real SpringBoard mode-validation failure, without suppressing it."""
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[1]
def require(value,reason):
    if not value:raise SystemExit(reason)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
# This is the immutable historical failure, independent of subsequent owned
# driver builds. Keep its exact candidate identity and original image input.
candidate=ROOT/'build/xnu-prelink/native-owner-legacy-display-info-candidate.macho'
plan=json.loads(candidate.with_suffix('.json').read_text())
require(sha(candidate)==plan['candidate_sha256']=='195cbd11ae3f63d8589c2c931c09ed292bb1e599398bcd920b13a893ec48c23e' and
        plan['original_sha256']=='f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7',
        'Exact previously qualified original-family baseline candidate; subsequent builds do not replace it')
path=ROOT/'build/darwinboot-owner-hvf-legacy-display-start-info-exception-SpringBoard-registers/gdb-stop.json'
d=json.loads(path.read_text())
symbol_path=ROOT/'build/native-legacy-display/info-SpringBoard-registers-symbolication.json'
s=json.loads(symbol_path.read_text())
require(d['kernel_sha256']==s['kernel_sha256']==plan['candidate_sha256'] and
        not d['bounded_timeout_interrupted'] and d['stop_symbol']=='_exception_triage' and
        d['actual_process']['name']==d['entry_process_name']=='SpringBoard',
        'Actual selected SpringBoard exception on the exact original-family candidate')
events=d['entry_process_events']
require(events and events[-1]['matched'] and events[-1]['process']==d['actual_process'] and
        all(not e['matched'] and e['process']['name']!='SpringBoard' for e in events[:-1]) and
        d['skipped_target_hits']==len(events)-1 and d['skipped_target_hits']>0,
        'Real bounded process selection skips unrelated exceptions without changing their execution')
require(len(d['entry_user_state_candidates'])==1,'Exactly one actual ARM64 saved EL0 state')
u=d['entry_user_state_candidates'][0]
regs=struct.unpack_from('<33Q',bytes.fromhex(u['saved_bytes']),8)
require(int(d['observed_function_entry_arguments'][0],16)==6 and
        struct.unpack('<2Q',bytes.fromhex(d['entry_regions']['1:0:10']['bytes']))==(1,regs[32]) and
        int(u['cpsr'],16)&31==0 and int(u['esr'],16)>>26==0x3c and
        u['instruction_bytes'].startswith('000020d4'),
        'Actual EXC_BREAKPOINT code, EL0 state, syndrome and unchanged BRK agree')
require(s['local_symbols_uuid_matches'] and
        int(s['frames'][0]['unslid_va'],16)==0x19f3d0744 and s['frames'][0]['offset']==580 and
        s['frames'][0]['nearest_local_symbol']=='-[FBSDisplayMode _initWithWidth:height:preferredScale:scaleOverride:refreshRate:gamut:hdr:rotation:virtual:validityCheck:]' and
        any(f['nearest_local_symbol']=='-[FBSDisplayConfiguration _initWithImmutableDisplay:originalDisplay:assertIfInvalid:]' for f in s['frames']),
        'UUID-bound original symbols identify the actual display mode validation call chain')
region=u['register_memory']['13:50'];raw=bytes.fromhex(region['bytes'])
require(int(region['address'],16)==regs[19] and len(raw)==80,'Read the actual preserved mode object through saved user x19')
isa,width,height,preferred,override,refresh,gamut,hdr,rotation,virtual=struct.unpack_from('<4Q2d3QB',raw)
require(isa and width==regs[25]==800 and height==regs[26]==600 and
        preferred==regs[24]==0 and override==0.0 and refresh==60.0 and
        (gamut,hdr,rotation,virtual)==(0,0,0,0),
        'Actual 800x600 mode has zero preferred/override scale and nonzero 60 Hz rate')
# The exact original initializer writes these fields and evaluates its own
# validity check. A missing capability is evidence to implement, not a reason
# to bypass this check or change original instructions.
cache=ROOT/'.cache/firmware/target-volumes/systemos-mount/System/Library/Caches/com.apple.dyld'
matched=False
for file in sorted(cache.glob('dyld_shared_cache_arm64*')):
    if file.suffix=='.symbols':continue
    with file.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as b:
        table,count=struct.unpack_from('<2I',b,16)
        for index in range(count):
            va,size,offset,_,protection=struct.unpack_from('<3Q2I',b,table+index*32)
            if va<=0x19f3d0500 and 0x19f3d0500+584<=va+size:
                at=offset+0x19f3d0500-va
                require(protection&4 and hashlib.sha256(b[at:at+584]).hexdigest()==
                        'ca4857e6617670f2369a0a6eb68be09e29135ce5dfda19ac1ea829229f0cc0ec',
                        'Exact unchanged original mode initializer and validation instructions')
                matched=True
require(matched,'Original executable mode initializer exists')
state=d['native_legacy_display']
require(state['stage']==10 and state['start_result']==state['dt_attached']==1 and
        state['client_calls']>=2 and not state['guard_slot'] and
        d['native_4k_mmu_observed'] and d['original_amfi_table_owner_observed'] and
        d['owner_root_binding_audit']['boot_root_accepted'] and
        d['actual_signature_failures']==dict(_cs_validate_page_bad_hash=0,_cs_validate_page_no_hash=0),
        'Real display service/client state, native 4K, original AMFI and independent root acceptance remain intact')
out=ROOT/'build/native-legacy-display/original-mode-validation-checkpoint.json'
out.write_text(json.dumps(dict(candidate_sha256=plan['candidate_sha256'],checkpoint_sha256=sha(path),
    symbolication_sha256=sha(symbol_path),actual_process=d['actual_process'],
    mode=dict(width=width,height=height,preferred_scale=preferred,scale_override=override,refresh_rate=refresh),
    historical_baseline=True,actual_original_validation_failure=True,original_instructions_modified=False,
    original_desktop=False,system_metal_device=False,adreno_execution=False,hardware_tested=False),indent=2)+'\n')
print('PASS: actual original SpringBoard mode-validation failure qualified; 800x600/60 Hz, both scales zero')
print('Historical missing-scale baseline only; current successful mode return is qualified by check-original-display-mode.py')
