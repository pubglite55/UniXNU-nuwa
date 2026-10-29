#!/usr/bin/env python3
"""Regenerate patches/mesa/turnip-darwin-kmd.patch from the working Mesa tree.

The patch is the difference between "pinned Mesa + the other recorded patches" and the working tree for the files the
Darwin backend touches, so it can be applied last. Edit the Mesa tree, run this, then run build-adreno-compiler-host.py to
prove the tree equals the recorded patches."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MESA = ROOT / '.cache/mesa-work'
NEW = ['src/freedreno/vulkan/tu_knl_darwin.cc']
MINE = ['meson.options', 'src/freedreno/vulkan/meson.build', 'src/freedreno/vulkan/tu_knl.cc',
        'src/freedreno/vulkan/tu_knl.h', 'src/freedreno/vulkan/tu_device.cc',
        'src/vulkan/wsi/wsi_common_metal_layer.m', 'src/util/cache_ops_aarch64.c'] + NEW
OUT = ROOT / 'patches/mesa/turnip-darwin-kmd.patch'
others = [p for p in json.loads((ROOT / 'scripts/data/adreno-compiler-inputs.json').read_text())['patches']
          if Path(p) != OUT.relative_to(ROOT)]


def git(tmp, *args, check=True):
    return subprocess.run(['git', '-c', 'user.email=a@b', '-c', 'user.name=n', *args], cwd=tmp, check=check,
                          capture_output=True, text=True).stdout


tmp = Path(tempfile.mkdtemp(dir=ROOT / '.cache'))
try:
    git(tmp, 'init', '-q')
    for f in MINE:
        if f in NEW:
            continue
        (tmp / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp / f).write_bytes(subprocess.run(['git', 'show', 'HEAD:' + f], cwd=MESA, check=True, capture_output=True).stdout)
    git(tmp, 'add', '-A')
    git(tmp, 'commit', '-q', '-m', 'base')
    for patch in others:
        for f in MINE:
            git(tmp, 'apply', '--include=' + f, str(ROOT / patch), check=False)
    git(tmp, 'add', '-A')
    git(tmp, 'commit', '-q', '-m', 'others', '--allow-empty')
    for f in MINE:
        (tmp / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(MESA / f, tmp / f)
    for f in NEW:
        git(tmp, 'add', '-N', f)
    OUT.write_text(git(tmp, 'diff', '--binary'))
finally:
    shutil.rmtree(tmp)
print('wrote', OUT.relative_to(ROOT), len(OUT.read_text().splitlines()), 'lines')
