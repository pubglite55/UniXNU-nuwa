#!/usr/bin/env python3
"""Extract one manifest-selected volume from the supplied iPad7,1 iPadOS 17 IPSW."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('component', choices=['OS', 'RestoreRamDisk', 'Cryptex1,SystemOS', 'Cryptex1,AppOS', 'StaticTrustCache', 'Cryptex1,SystemTrustCache'])
parser.add_argument('--ipsw', type=Path, default=ROOT / 'refer/iPad_Pro_HFR_17.7.11_21H461_Restore.ipsw')
args = parser.parse_args()
out = ROOT / '.cache/firmware/target-volumes'
out.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(args.ipsw) as archive:
    manifest = plistlib.loads(archive.read('BuildManifest.plist'))
    if (manifest['ProductVersion'] != '17.7.11' or manifest['ProductBuildVersion'] != '21H461'
            or 'iPad7,1' not in manifest['SupportedProductTypes']):
        raise SystemExit('Use only the supplied iPad7,1 iPadOS 17.7.11 / 21H461 input')
    identity = next(item for item in manifest['BuildIdentities']
                    if item['Info']['DeviceClass'] == 'j120ap' and item['Info']['RestoreBehavior'] == 'Erase'
                    and int(item['ApChipID'], 16) == 0x8011 and int(item['ApBoardID'], 16) == 12)
    component = identity['Manifest'][args.component]
    member = component['Info']['Path']
    entry = archive.getinfo(member)
    destination = out / Path(member).name
    if destination.exists():
        raise SystemExit(f'Input already exists; inspect its saved hash before replacing: {destination.name}')
    temporary = destination.with_suffix('.partial')
    digest = hashlib.sha256()
    count = 0
    try:
        with archive.open(entry) as source, temporary.open('xb') as target:
            while chunk := source.read(8 * 1024 * 1024):
                target.write(chunk)
                digest.update(chunk)
                count += len(chunk)
        if count != entry.file_size:
            raise SystemExit('Incomplete volume extraction')
        temporary.rename(destination)
    finally:
        temporary.unlink(missing_ok=True)
    report = {'product': 'iPad7,1', 'board': 'j120ap', 'version': manifest['ProductVersion'],
              'build': manifest['ProductBuildVersion'], 'identity': 'Erase', 'component': args.component,
              'member': member, 'size': count, 'sha256': digest.hexdigest(),
              'zip_crc_verified': True, 'mounted': False, 'userspace_boot_demonstrated': False}
    destination.with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
