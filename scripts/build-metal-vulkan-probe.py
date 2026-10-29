#!/usr/bin/env python3
"""Build an offline exact-policy AIR/SPIR-V probe, with no Vulkan loader or GPU."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = json.loads((ROOT / 'scripts/data/gpu-metal-vulkan-inputs.json').read_text())['translator']['commit']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--translator-source', type=Path,
                        default=ROOT / '.cache/gpu-reference/metal2vulkan')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/gpu-001/compiler')
    args = parser.parse_args()
    source, output = args.translator_source.resolve(), args.output.resolve()
    (output / 'build-report.json').unlink(missing_ok=True)
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != PIN:
        raise SystemExit('Translator revision differs from the qualified source pin')
    if subprocess.check_output(['git', '-C', str(source), 'diff', 'HEAD', '--'], text=True):
        raise SystemExit('Translator source must be unmodified')
    toolchain = subprocess.check_output(['rustc', '+1.98.0', '--version'], text=True).strip()
    if not toolchain.startswith('rustc 1.98.0 '):
        raise SystemExit('This probe requires Rust 1.98.0')
    output.mkdir(parents=True, exist_ok=True)
    manifest = output / 'Cargo.toml'
    # Only generated build files contain local dependency paths.
    manifest.write_text('\n'.join([
        '[package]', 'name = "adreno-metal-vulkan-probe"', 'version = "0.1.0"',
        'edition = "2021"', 'rust-version = "1.98"', '[workspace]',
        '[[bin]]', 'name = "adreno-metal-vulkan-probe"',
        'path = ' + json.dumps(str(ROOT / 'drivers/AdrenoMetal/tools/MetalVulkanProbe.rs')),
        '[dependencies]',
        'metal2vulkan = { path = ' + json.dumps(str(source / 'crates/metal2vulkan')) + ', features = ["serde"] }',
        'serde_json = "=1.0.154"', '[profile.release]', 'incremental = true',
        '',
    ]))
    shutil.copyfile(ROOT / 'drivers/AdrenoMetal/tools/metal-vulkan-probe.lock', output / 'Cargo.lock')
    target = output / 'target'
    command = ['cargo', '+1.98.0', 'build', '--release', '--locked', '--manifest-path', str(manifest),
               '--target-dir', str(target), '-j4']
    with (output / 'build.log').open('w') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    if result.returncode:
        raise SystemExit((output / 'build.log').read_text()[-6000:])
    binary = target / 'release/adreno-metal-vulkan-probe'
    report = dict(translator_revision=revision, rustc=toolchain,
                  source_sha256=digest(ROOT / 'drivers/AdrenoMetal/tools/MetalVulkanProbe.rs'),
                  cargo_lock_sha256=digest(output / 'Cargo.lock'), binary_sha256=digest(binary),
                  policy='exact_answers+exact_sampling', gpu_execution=False,
                  hardware_capabilities_observed=False, binary=str(binary))
    (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
