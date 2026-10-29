# SPDX-License-Identifier: MIT
"""Verify overlapping recorded Mesa patches without mutating the source tree."""
from pathlib import Path
import re
import subprocess
import tempfile


def validate_recorded_patches(root, source, pins):
    paths = set()
    for patch in pins['patches']:
        text = (root / patch).read_text()
        paths.update(re.findall(r'^diff --git a/(\S+) b/\1$', text, re.M))
    changed = set(subprocess.check_output(['git', '-C', source, 'diff', 'HEAD', '--name-only'], text=True).splitlines())
    changed.update(subprocess.check_output(['git', '-C', source, 'ls-files', '--others', '--exclude-standard'], text=True).splitlines())
    if changed - paths:
        raise SystemExit('Unrecorded Mesa source changes: ' + ', '.join(sorted(changed - paths)))
    with tempfile.TemporaryDirectory(prefix='mesa-patch-check-', dir=root / '.cache') as name:
        stripped = Path(name)
        subprocess.run(['git', 'init', '-q', str(stripped)], check=True, capture_output=True, timeout=20)
        for path in paths:
            actual = source / path
            if actual.is_file():
                if actual.is_symlink():
                    raise SystemExit('Unexpected source symlink: ' + path)
                destination = stripped / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(actual.read_bytes())
        for patch in reversed(pins['patches']):
            result = subprocess.run(['git', 'apply', '--reverse', str(root / patch)], cwd=stripped,
                                    capture_output=True, text=True, timeout=20)
            if result.returncode:
                raise SystemExit('Recorded Mesa patch sequence differs: ' + patch + '\n' + result.stderr)
        for path in paths:
            original = subprocess.run(['git', '-C', source, 'show', 'HEAD:' + path], capture_output=True, timeout=20)
            actual = stripped / path
            if (original.returncode == 0 and (not actual.is_file() or actual.read_bytes() != original.stdout)) or (original.returncode != 0 and actual.exists()):
                raise SystemExit('Recorded Mesa patches do not reconstruct pinned source: ' + path)
