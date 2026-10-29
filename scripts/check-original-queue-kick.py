#!/usr/bin/env python3
"""Check actual pending-request ownership at the original no-op queue kick."""
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'kits/XnuPrelink'))
from native_prelink import macho,backed_offset
def require(v,s):
    if not v:raise SystemExit(s)
kernel=ROOT/'build/xnu-prelink/native-owner-legacy-display-validate-candidate.macho'
raw=kernel.read_bytes();image=macho(raw)
require(hashlib.sha256(raw).hexdigest()=='0c8e25d34b4e4987bd96794abecab882f796992691b008779e77a5111cb84497','Exact historical validation candidate')
offset=backed_offset(image['segments'],0xfffffff005794030,16,len(raw))
require(raw[offset:offset+16]==bytes.fromhex('ff4300d1e00700f9ff430091c0035fd6'),'Exact unchanged original no-op queue-kick body')
path=ROOT/'build/darwinboot-owner-hvf-offline-legacy-swap-driver-pm-kick/gdb-stop.json'
d=json.loads(path.read_text());l=d['native_legacy_display']
require(d['kernel_sha256']==hashlib.sha256(raw).hexdigest() and not d['bounded_timeout_interrupted'] and
        int(d['pc'],16)==0xfffffff005794030 and int(d['x30'],16)==0xfffffff00579196c and
        d['primary_start_event']['pc']=='0xfffffff00bf4e18c','Real original queue kick reached after actual own validator checkpoint')
tail=bytes.fromhex(d['entry_regions']['0:1000:800']['bytes'])
current,pending=struct.unpack_from('<2Q',tail,5472-4096)
require(current==0 and pending==l['swap_request'] and pending and l['swap_validation_result']==1 and
        l['swap_validation_reason']==0 and l['swap_validation_calls']==1 and not l['guard_slot'],
        'Actual pending queue owns the identical validated original request, with no current request')
require(d['native_4k_mmu_observed'] and d['original_amfi_table_owner_observed'] and d['owner_root_binding_audit']['boot_root_accepted'],'Original AMFI/root and native 4K intact')
print('PASS: original queue owns the real validated request; its unchanged queue-kick implementation does no work')
