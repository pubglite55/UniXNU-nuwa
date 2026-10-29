#!/usr/bin/env python3
"""Verify the actual original valid-packet branch that bypasses submission."""
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
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
kernel=ROOT/'build/xnu-prelink/native-owner-legacy-display-scale-candidate.macho'
raw=kernel.read_bytes();image=macho(raw);plan=json.loads(kernel.with_suffix('.json').read_text())
require(sha(kernel)==plan['candidate_sha256'],'Exact observed kernel')
def read(a,n):
    o=backed_offset(image['segments'],a,n,len(raw));return raw[o:o+n]
# Exact original path: load self+5836, compare to zero, set bypass byte
# when zero, then skip the actual submit helper if packet-valid AND bypass.
words=struct.unpack('<21I',read(0xfffffff00579056c,84))
require(words==(0xf94063e8,0xb956cd08,0x71000108,0x1a9f07e8,0x370000a8,
                0x14000001,0x52800028,0x3819f3a8,0x14000001,0x3859e3a8,
                0x360001c8,0x14000001,0x3859f3a8,0x36000088,0x14000001,
                0xb81ac3bf,0x14000007,0xf94063e0,0xf9404be8,0xf9400101,
                0x940000fc),'Exact original gate branch and submit call bytes')
path=ROOT/'build/darwinboot-owner-hvf-offline-legacy-swap-decision/gdb-stop.json'
d=json.loads(path.read_text())
require(d['kernel_sha256']==plan['candidate_sha256'] and not d['bounded_timeout_interrupted'] and
        int(d['pc'],16)==0xfffffff005790574 and int(d['x8'],16)==0,
        'Actual original load observes submission-control value zero')
frame=d['frame_chain'][0];local=bytes.fromhex(frame['local_bytes']);fp=int(frame['fp'],16);base=int(frame['local_address'],16)
require(local[fp-98-base]==1,'Actual original packet-validation result true')
packet=bytes.fromhex(d['frame_indirect_memory']['0:-28:508']['bytes'])
require(len(packet)==1288 and struct.unpack_from('<2I',packet,152)==(1,1) and
        struct.unpack_from('<2I',packet,180)==(800,600) and
        struct.unpack_from('<2I',packet,276)==(800,600),'Actual generation, surface ID and rectangles reach kernel')
require(d['native_4k_mmu_observed'] and d['original_amfi_table_owner_observed'] and
        d['owner_root_binding_audit']['boot_root_accepted'] and not d['native_legacy_display']['guard_slot'],
        'Native 4K, original root/AMFI and unchanged backend remain intact')
(ROOT/'build/offline-legacy-swap/gate-checkpoint.json').write_text(json.dumps(dict(
    report_sha256=sha(path),kernel_sha256=sha(kernel),original_packet_valid=True,actual_control_value=0,
    branch_analysis='original valid-and-bypass path skips actual submit helper',
    private_state_modified=False,original_desktop=False),indent=2)+'\n')
print('PASS: actual original packet is valid, but its real zero submission control selects the original bypass path')
