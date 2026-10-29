#!/usr/bin/env python3
"""Bundle only the two unchanged original target trust-cache modules."""
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def der(data, at):
    if at + 2 > len(data):
        raise ValueError('Truncated DER')
    tag, size = data[at:at + 2]
    at += 2
    if size & 128:
        count = size & 127
        if not 0 < count <= 4 or at + count > len(data):
            raise ValueError('Invalid DER length')
        size = int.from_bytes(data[at:at + count], 'big')
        at += count
    if at + size > len(data):
        raise ValueError('DER exceeds original input')
    return tag, data[at:at + size], at + size


with zipfile.ZipFile(ROOT / 'refer/iPad_Pro_HFR_17.7.11_21H461_Restore.ipsw') as archive:
    manifest = plistlib.loads(archive.read('BuildManifest.plist'))
    identities = [i for i in manifest['BuildIdentities'] if i['Info']['DeviceClass'] == 'j120ap']
    if manifest['ProductBuildVersion'] != '21H461' or len(identities) != 2:
        raise SystemExit('Require supplied ordinary-ARM64 iPad7,1 target')
    entry = identities[0]['Manifest']['Cryptex1,SystemTrustCache']
    original = archive.read(entry['Info']['Path'])
    if any(i['Manifest']['Cryptex1,SystemTrustCache']['Digest'] != hashlib.sha384(original).digest() for i in identities):
        raise SystemExit('Both original manifest digests must match')
tag, sequence, end = der(original, 0)
fields, cursor = [], 0
while cursor < len(sequence):
    kind, data, cursor = der(sequence, cursor)
    fields.append((kind, data))
if tag != 0x30 or end != len(original) or [kind for kind, _ in fields] != [0x16, 0x16, 0x16, 4] or fields[0][1] != b'IM4P':
    raise SystemExit('Require the original System trust-cache IM4P')
system = fields[3][1]
static = (ROOT / '.cache/firmware/target-volumes/static-trustcache.bin').read_bytes()
expected = ('da88460e6e513438d5307e5c526f76497a74754476a24da29f239f0c90120fc2',
            'd121ba89167e03aafd00fa687c30cd8ebc4ccafd10c1408adb2ba3de12403651')
for module, digest in zip((static, system), expected):
    if (hashlib.sha256(module).hexdigest() != digest or struct.unpack_from('<I', module)[0] != 2 or
            len(module) != 24 + struct.unpack_from('<I', module, 20)[0] * 24):
        raise SystemExit('Require complete exact original version-2 trust module')
bundle = struct.pack('<3I', 2, 12, 12 + len(static)) + static + system
out = ROOT / 'build/original-static-system-trust'
out.mkdir(parents=True, exist_ok=True)
(out / 'original-static-system.bundle').write_bytes(bundle)
(out / 'inputs.json').write_text(json.dumps(dict(original_static_sha256=expected[0], original_system_sha256=expected[1],
    original_im4p_sha256=hashlib.sha256(original).hexdigest(), bundle_sha256=hashlib.sha256(bundle).hexdigest(),
    own_code_entries_added=False, original_modules_modified=False, apple_personalization_claimed=False), indent=2) + '\n')
print('Bundled only two unchanged original modules:', hashlib.sha256(bundle).hexdigest())
