#!/usr/bin/env python3
"""Identify the supplied target's real root-hash payloads without claiming trust."""
import hashlib
import json
from pathlib import Path
import plistlib
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def tlv(data, at):
    tag, size = data[at:at + 2]
    at += 2
    if size & 128:
        count = size & 127
        if not 0 < count <= 4:
            raise SystemExit('Expected definite bounded DER length')
        size = int.from_bytes(data[at:at + count], 'big')
        at += count
    end = at + size
    if end > len(data):
        raise SystemExit('DER element extends beyond the actual input')
    return tag, data[at:end], end


with zipfile.ZipFile(ROOT / 'refer/iPad_Pro_HFR_17.7.11_21H461_Restore.ipsw') as archive:
    manifest = plistlib.loads(archive.read('BuildManifest.plist'))
    identities = [i for i in manifest['BuildIdentities'] if i['Info']['DeviceClass'] == 'j120ap']
    if manifest['ProductBuildVersion'] != '21H461' or len(identities) != 2:
        raise SystemExit('Expected the supplied 2017 target build and both actual restore identities')
    records = []
    for name in ('SystemVolume', 'Cryptex1,SystemVolume', 'Cryptex1,AppVolume'):
        component = identities[0]['Manifest'][name]
        path = component['Info']['Path']
        data = archive.read(path)
        tag, sequence, end = tlv(data, 0)
        if tag != 0x30 or end != len(data):
            raise SystemExit('Expected one complete actual DER sequence')
        fields, cursor = [], 0
        while cursor < len(sequence):
            kind, value, cursor = tlv(sequence, cursor)
            fields.append((kind, value))
        if [t for t, _ in fields] != [0x16, 0x16, 0x16, 4] or fields[0][1] != b'IM4P':
            raise SystemExit('Expected actual IM4P fields, without fabricating an Image4 manifest')
        digest = hashlib.sha384(data).digest()
        if any(i['Manifest'][name]['Digest'] != digest or
               i['Manifest'][name]['Info']['Path'] != path or
               i['Manifest'][name]['Info'].get('Personalize') is not True for i in identities):
            raise SystemExit('Root-hash input disagrees with the actual target restore manifests')
        records.append(dict(component=name, member=path, bytes=len(data),
                            sha256=hashlib.sha256(data).hexdigest(), sha384=digest.hex(),
                            image4_payload_type=fields[1][1].decode(), im4p_version=fields[2][1].decode(),
                            payload_bytes=len(fields[3][1]),
                            payload_sha256=hashlib.sha256(fields[3][1]).hexdigest(),
                            both_manifest_digests_match=True, personalize_required=True,
                            personalized_im4m_present=False, signature_authentication_qualified=False))
report = dict(target='iPad7,1', board='j120ap', build='21H461', root_hash_inputs=records,
              build_manifest_digest_check_is_not_signature_authentication=True,
              root_authentication_solved=False, hardware_tested=False)
out = ROOT / 'build/target-root-hash-inputs.json'
out.write_text(json.dumps(report, indent=2) + '\n')
print('PASS: three real 229-byte IM4P root-hash inputs match both original target manifest digests')
print('All require personalization; these payloads alone do not supply a personalized IM4M or authenticate a boot root')
