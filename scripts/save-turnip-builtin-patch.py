#!/usr/bin/env python3
"""Record only the builtin-cache change over the other pinned Mesa patches."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MESA = ROOT / '.cache/mesa-work'
OUT = ROOT / 'patches/mesa/turnip-builtin-shader-pack.patch'
FILES = ['meson.options', 'src/freedreno/vulkan/meson.build', 'src/freedreno/vulkan/tu_device.cc',
         'src/freedreno/vulkan/tu_device.h', 'src/freedreno/vulkan/tu_shader.cc',
         'src/freedreno/vulkan/tu_clear_blit.cc']
NEW = ['src/freedreno/vulkan/tu_builtin_cache.cc', 'src/freedreno/vulkan/tu_builtin_cache.h']


def git(directory, *args):
    return subprocess.check_output(['git', '-c', 'user.email=a@b', '-c', 'user.name=n', *args], cwd=directory)


with tempfile.TemporaryDirectory(dir=ROOT / '.cache', prefix='builtin-patch-') as name:
    tmp = Path(name)
    git(tmp, 'init', '-q')
    for path in FILES:
        (tmp / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp / path).write_bytes(git(MESA, 'show', 'HEAD:' + path))
    for patch in json.loads((ROOT / 'scripts/data/adreno-compiler-inputs.json').read_text())['patches']:
        if patch != str(OUT.relative_to(ROOT)):
            git(tmp, 'apply', *['--include=' + path for path in FILES], str(ROOT / patch))
    git(tmp, 'add', '-A')
    git(tmp, 'commit', '-q', '-m', 'recorded-base')
    for path in FILES + NEW:
        (tmp / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(MESA / path, tmp / path)
    git(tmp, 'add', '-N', *NEW)
    OUT.write_bytes(git(tmp, 'diff', '--binary'))
print('Recorded builtin-cache source patch')
