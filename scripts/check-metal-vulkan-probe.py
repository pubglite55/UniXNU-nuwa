#!/usr/bin/env python3
"""Exercise real translator refusals; never opens a Vulkan device."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--air-input-dir', required=True, type=Path)
    parser.add_argument('--compiler-build', type=Path, default=ROOT / 'build/gpu-001/compiler')
    args = parser.parse_args()
    build = json.loads((args.compiler_build / 'build-report.json').read_text())
    binary = Path(build['binary'])
    if hashlib.sha256(binary.read_bytes()).hexdigest() != build['binary_sha256'] or \
            hashlib.sha256((ROOT / 'drivers/AdrenoMetal/tools/MetalVulkanProbe.rs').read_bytes()).hexdigest() != build['source_sha256']:
        raise SystemExit('Compiler identity mismatch')
    profile = ROOT / '.cache/gpu-reference/metal2vulkan/crates/metal2vulkan-validation/profiles/vk12-bare.json'
    vertex = args.air_input_dir / 'QuartzCore/module-7.bc'
    fragment = args.air_input_dir / 'QuartzCore/module-65.bc'
    layout = ROOT / 'drivers/AdrenoMetal/tools/probe-vertex-layout.json'
    colors = ROOT / 'drivers/AdrenoMetal/tools/probe-coverage-attachment.json'
    audit = json.loads((args.air_input_dir / 'target-inputs.json').read_text())
    records = {(m['library'], m['index']): m for m in audit['modules']}
    for path, index in [(vertex, 7), (fragment, 65)]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != records[('QuartzCore', index)]['bitcode_sha256']:
            raise SystemExit('Original module hash mismatch')
    vname, fname = (records[('QuartzCore', i)]['name'] for i in [7, 65])
    with tempfile.TemporaryDirectory(prefix='controls-', dir=ROOT / 'build/gpu-001') as temporary:
        work = Path(temporary)
        malformed = work / 'malformed.bc'
        malformed.write_bytes(b'BC\xc0\xde')
        bad_profile = work / 'profile.json'
        bad_profile.write_text('{}')
        bad_layout = work / 'layout.json'
        bad_layout.write_text(json.dumps(dict(layouts={}, attributes={
            '0': dict(format='Float4', offset=0, buffer_index=0)})))
        controls = [
            ('truncated-bitcode', ['--list', malformed]),
            ('invalid-profile', [bad_profile, vertex, vname]),
            ('missing-entry', [profile, vertex, '__absent_entry__']),
            ('standalone-fragment', [profile, fragment, fname]),
            ('wrong-fragment-stage', ['--vertex-descriptor', layout, profile, vertex, vname, vertex, vname]),
            ('missing-vertex-layout', ['--vertex-descriptor', bad_layout, profile, vertex, vname]),
            ('missing-color-attachment', ['--vertex-descriptor', layout, profile, vertex, vname, fragment, fname]),
            ('incompatible-varyings', ['--vertex-descriptor', layout, '--color-attachments', colors,
                                       profile, vertex, vname, fragment, fname]),
        ]
        for name, command in controls:
            result = subprocess.run([str(binary), *map(str, command)], capture_output=True, text=True, timeout=20)
            if result.returncode != 2 or result.stdout.strip() or not result.stderr.startswith('REFUSED:'):
                raise AssertionError(f'{name}: failed closed-boundary check: {result.returncode}')
        # A changed inventory must fail before any translation output is created.
        (work / 'target-inputs.json').write_text((args.air_input_dir / 'target-inputs.json').read_text() + '\n')
        result = subprocess.run(['python3', '-B', str(ROOT / 'scripts/probe-metal-vulkan-host.py'),
                                 '--air-input-dir', str(work), '--compiler-build', str(args.compiler_build),
                                 '--output', str(work / 'refused-output')], capture_output=True, text=True, timeout=20)
        if result.returncode == 0 or (work / 'refused-output').exists() or 'pinned original inventory' not in result.stderr:
            raise AssertionError('Changed target inventory was not refused before output')
    print('PASS: eight actual parser/pipeline refusals and changed-inventory refusal; no GPU execution')


if __name__ == '__main__':
    main()
