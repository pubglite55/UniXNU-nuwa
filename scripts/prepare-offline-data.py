#!/usr/bin/env python3
"""Create the offline 32 MiB APFS Data skeleton used by the deeper boot tests.

The seed fixture has the common iOS Data directories but lacks the
user-management skeleton. This adds only empty directories (no keys, no user
records, no Apple data) so usermanagerd can create its own system/default/
personal personas. QEMU-only test input; not a restore or provisioned device.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / 'build/offline-renderbox-present-2/compiler-data-32.cdr'
OUTPUT = ROOT / 'build/offline-renderbox-present-2/compiler-data-32-boot.cdr'
REPORT = ROOT / 'build/armdt-platform/data-provision.json'
DIRECTORIES = (
    'db', 'db/dslocal', 'db/dslocal/nodes', 'db/dslocal/nodes/Default',
    'db/dslocal/nodes/Default/users', 'db/dslocal/nodes/Default/groups',
    'db/dslocal/nodes/Default/config',
    'containers', 'containers/Data', 'containers/Data/System',
    'containers/Data/Application', 'containers/Shared',
    'containers/Shared/SystemGroup',
    'PersonaVolumes', 'preboot', 'root', 'tmp', 'Library',
    'keybags', 'keybags/backup',
    'mobile/Library/Preferences', 'mobile/Library/Caches', 'mobile/Library/Logs',
    'mobile/Containers', 'mobile/Documents', 'mobile/Media', 'mobile/tmp',
)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--seed', type=Path, default=SEED)
parser.add_argument('--report', type=Path, default=REPORT)
parser.add_argument('--output', type=Path, default=OUTPUT)
parser.add_argument('--check-existing', action='store_true')
args = parser.parse_args()
SEED = args.seed.resolve()
REPORT = args.report.resolve()
args.output = args.output.resolve()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


if args.check_existing:
    if not args.output.exists():
        raise SystemExit(f'Missing provisioned Data fixture: {args.output}')
    print(json.dumps({'path': str(args.output), 'bytes': args.output.stat().st_size,
                      'sha256': sha256(args.output)}, indent=2))
    raise SystemExit(0)

if not SEED.exists():
    raise SystemExit(f'Missing Data seed: {SEED}')
if args.output.exists():
    raise SystemExit(f'Refuse to overwrite the existing fixture: {args.output}')
args.output.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(SEED, args.output)
mount = args.output.parent / (args.output.stem + '-mount')
mount.mkdir(parents=True, exist_ok=True)
info = plistlib.loads(subprocess.check_output(
    ['hdiutil', 'attach', '-nobrowse', '-owners', 'off', '-mountpoint', str(mount),
     str(args.output), '-plist']))
device = info['system-entities'][0]['dev-entry']
created = []
def file_inventory():
    # Prove no original file or symlink changes while adding directories.
    import os
    result = {}
    for current, dirs, files in os.walk(mount, followlinks=False):
        for name in dirs + files:
            path = Path(current) / name
            key = str(path.relative_to(mount))
            if path.is_symlink(): result[key] = ['symlink', os.readlink(path)]
            elif path.is_file(): result[key] = ['file', sha256(path)]
    return result
try:
    before = file_inventory()
    for name in DIRECTORIES:
        path = mount / name
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            created.append(name)
    after = file_inventory()
    if before != after:
        raise RuntimeError('File/symlink changed during directory-only preparation')
    volumes = [e for e in info['system-entities'] if e.get('mount-point') == str(mount)]
    if len(volumes) != 1: raise RuntimeError('Expected one mounted Data volume')
    volume = plistlib.loads(subprocess.check_output(['diskutil','info','-plist',volumes[0]['dev-entry']]))
finally:
    subprocess.run(['hdiutil', 'detach', device], check=True, capture_output=True)
    mount.rmdir()
result = {
    'source_seed': str(SEED.relative_to(ROOT)),
    'source_seed_sha256': sha256(SEED),
    'fixture': str(args.output.relative_to(ROOT)),
    'fixture_sha256': sha256(args.output),
    'fixture_bytes': args.output.stat().st_size,
    'directories': list(DIRECTORIES),
    'created': created,
    'added_keys_or_user_records': False,
    'original_file_symlink_inventory_unchanged': before == after,
    'original_file_symlink_count': len(before),
    'volume_uuid': volume['VolumeUUID'],
    'qemu_only': True,
}
REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
