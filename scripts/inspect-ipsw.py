#!/usr/bin/env python3
"""Inspect a local restore image without extracting its root filesystem."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import zipfile


def inspect(path, extract=False, output=Path('.cache/firmware')):
    with zipfile.ZipFile(path) as archive:
        manifest = plistlib.loads(archive.read('BuildManifest.plist'))
        if 'iPad7,1' not in manifest['SupportedProductTypes']:
            raise ValueError('IPSW does not support iPad7,1')
        if not manifest['ProductVersion'].startswith('17.'):
            raise ValueError('IPSW is not iPadOS 17')
        identity = next(b for b in manifest['BuildIdentities']
                        if b['Info']['DeviceClass'] == 'j120ap'
                        and b['Info']['RestoreBehavior'] == 'Erase')
        report = {
            'version': manifest['ProductVersion'],
            'build': manifest['ProductBuildVersion'],
            'products': manifest['SupportedProductTypes'],
            'board': identity['Info']['DeviceClass'],
            'chip_id': identity['ApChipID'],
            'board_id': identity['ApBoardID'],
            'components': {},
        }
        names = {kind: identity['Manifest'][kind]['Info']['Path']
                 for kind in ('KernelCache', 'DeviceTree', 'RestoreRamDisk', 'OS')}
        needed = sum(archive.getinfo(names[k]).file_size
                     for k in ('KernelCache', 'DeviceTree'))
        for kind, name in names.items():
            entry = {'member': name, 'size': archive.getinfo(name).file_size}
            if kind in ('KernelCache', 'DeviceTree'):
                data = archive.read(name)
                entry['sha256'] = hashlib.sha256(data).hexdigest()
                entry['magic_hex'] = data[:16].hex()
                if extract:
                    output.mkdir(parents=True, exist_ok=True)
                    destination = output / Path(name).name
                    destination.write_bytes(data)
                    entry['extracted'] = destination.as_posix()
            report['components'][kind] = entry
        return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ipsw', type=Path)
    parser.add_argument('--extract', action='store_true')
    parser.add_argument('--output', type=Path, default=Path('.cache/firmware'))
    args = parser.parse_args()
    print(json.dumps(inspect(args.ipsw, args.extract, args.output), indent=2))
