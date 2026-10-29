#!/usr/bin/env python3
"""Package unchanged supplied launchd/dyld for a bounded offline native-4K test."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=ROOT / 'build/target-dyld-fixture')
args = parser.parse_args()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=True)
volume = ROOT / '.cache/firmware/target-volumes/os-mount'
inputs = [('sbin/launchd', '8cec9a3c44a443b08e977ccc5d577850316ad428c575dc01f09b018dbd5b6a25'),
          ('usr/lib/dyld', 'f8df3c58fae6e409db740df22c98aa699aee110b73523541a63f1bd5e23cf705')]
files = []
for name, expected in inputs:
    data = (volume / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit('Expected the exact supplied 21H461 ' + name)
    if struct.unpack_from('<3I', data) != (0xfeedfacf, 0x100000c, 0):
        raise SystemExit('Target must remain ordinary ARM64 subtype zero')
    files.append(data)
    (out / Path(name).name).write_bytes(data)
launchd, dyld = files
test_offset = (4096 + len(launchd) + 4095) & ~4095
image = bytearray((test_offset + len(dyld) + 4095) & ~4095)
struct.pack_into('<8sII4Q', image, 0, b'N4KROOT\0', 1, 2, 4096, len(launchd), test_offset, len(dyld))
image[4096:4096 + len(launchd)] = launchd
image[test_offset:test_offset + len(dyld)] = dyld
(out / 'root.img').write_bytes(image)
tc = (ROOT / '.cache/firmware/target-volumes/static-trustcache.bin').read_bytes()
if hashlib.sha256(tc).hexdigest() != 'da88460e6e513438d5307e5c526f76497a74754476a24da29f239f0c90120fc2':
    raise SystemExit('Expected the exact supplied original static trust-cache module')
if struct.unpack_from('<I', tc)[0] != 2 or len(tc) != 24 + struct.unpack_from('<I', tc, 20)[0] * 24:
    raise SystemExit('Unexpected original trust-cache format')
cdhashes = ['1d52c69747dffc4b1937d241bdbc9cee3b22df18', 'b479f90e05545314cb843410c3d98ef84d926710']
entries = [tc[i:i + 20] for i in range(24, len(tc), 24)]
if any(bytes.fromhex(h) not in entries for h in cdhashes):
    raise SystemExit('Original launchd/dyld CDHashes must exist in the unchanged original module')
bundle = struct.pack('<2I', 1, 8) + tc
(out / 'original-static-trust.bundle').write_bytes(bundle)
entry = None
at = 32
for _ in range(struct.unpack_from('<I', dyld, 16)[0]):
    cmd, length = struct.unpack_from('<II', dyld, at)
    if cmd == 5:
        flavor, words = struct.unpack_from('<II', dyld, at + 8)
        if (flavor, words) != (6, 68):
            raise SystemExit('Unexpected original ARM_THREAD_STATE64')
        entry = struct.unpack_from('<Q', dyld, at + 16 + 32 * 8)[0]
    at += length
if entry is None:
    raise SystemExit('Missing original dynamic linker entry')
branch = struct.unpack_from('<I', dyld, entry + 16)[0]
if branch & 0xfc000000 != 0x14000000:
    raise SystemExit('Expected the original dyld startup direct branch')
displacement = branch & 0x3ffffff
if displacement & 0x2000000:
    displacement -= 0x4000000
startup = entry + 16 + displacement * 4
nm = subprocess.check_output(['xcrun', 'nm', '-U', out / 'dyld'], text=True)
symbol_names = {'_mach_init', '_vm_page_size', '_vm_page_shift', '_vm_kernel_page_shift', '_vm_page_mask',
                '__ZN5dyld4L7prepareERNS_4APIsEPKN5dyld313MachOAnalyzerE'}
dyld_symbols = {name: int(at, 16) for at, name in re.findall(r'^([0-9a-fA-F]+)\s+\S\s+(\S+)$', nm, re.M)
                if name in symbol_names}
if set(dyld_symbols) != symbol_names:
    raise SystemExit('Missing original dyld page-ABI symbols')
metadata = dict(target='iPad7,1 / 17.7.11 / 21H461',
                files=[dict(path=n, sha256=h) for n, h in inputs], original_cdhashes=cdhashes,
                root_sha256=hashlib.sha256(image).hexdigest(), root_bytes=len(image),
                original_static_module_sha256=hashlib.sha256(tc).hexdigest(),
                trust_bundle_sha256=hashlib.sha256(bundle).hexdigest(), dyld_preferred_entry=entry,
                dyld_startup_checkpoint=startup + 4,
                dyld_symbols=dyld_symbols,
                original_files_or_trust_module_modified=False, apple_boot_trust_chain_verified=False,
                test_instrument_only=True)
(out / 'inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')
print('Packaged unchanged supplied launchd/dyld and unchanged original trust-cache module')
print(f'Offline root: {len(image)} bytes; preferred dyld entry: {entry:#x}; no hardware operations')
