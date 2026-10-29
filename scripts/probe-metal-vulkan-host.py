#!/usr/bin/env python3
"""Bounded target AIR parsing/translation; profiles are hypothetical, never GPU evidence."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
PINS = json.loads((ROOT / 'scripts/data/gpu-metal-vulkan-inputs.json').read_text())
SOURCE_PIN = PINS['translator']['commit']
INVENTORY_PIN = PINS['target_air_inventory_sha256']
LIBRARIES = {
    'QuartzCore': '606f913adf520420f9b4bb666efb782a68c830f082f1e559e17b20d0d13adbc9',
    'RenderBox': 'd76883f626b1527c36fb0940cf27dcade503a55cf2fa05c8f7a247a40ccebec4',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def output_stores(words):
    """Count direct/access-chain stores to declared SPIR-V Output variables."""
    variables, bases, stores = set(), {}, []
    offset = 5
    while offset < len(words):
        count, opcode = words[offset] >> 16, words[offset] & 0xffff
        if not count or offset + count > len(words):
            raise ValueError('Invalid SPIR-V instruction extent')
        instruction = words[offset:offset + count]
        if opcode == 59 and count >= 4 and instruction[3] == 3:
            variables.add(instruction[2])
        elif opcode in (65, 66, 67) and count >= 4:
            bases[instruction[2]] = instruction[3]
        elif opcode == 62 and count >= 3:
            stores.append(instruction[1])
        offset += count
    observed = 0
    for pointer in stores:
        visited = set()
        while pointer in bases and pointer not in visited:
            visited.add(pointer)
            pointer = bases[pointer]
        observed += pointer in variables
    return dict(declared_output_variables=len(variables), output_store_instructions=observed)


def worker(command, directory):
    """A separate process group per attempt; watch RSS and bound output and time."""
    directory.mkdir()
    start = time.monotonic()
    peak = 0
    failure = None
    with (directory / 'stdout.json').open('wb') as out, (directory / 'stderr.log').open('wb') as err:
        process = subprocess.Popen([str(x) for x in command], stdout=out, stderr=err, start_new_session=True)
        try:
            while process.poll() is None:
                sample = subprocess.run(['ps', '-o', 'rss=', '-p', str(process.pid)],
                                        capture_output=True, text=True, timeout=1)
                if sample.returncode == 0 and sample.stdout.strip():
                    peak = max(peak, int(sample.stdout.strip()) * 1024)
                if peak > 500 * 1024**2:
                    failure = 'resident-memory budget exceeded'
                elif time.monotonic() - start > 20:
                    failure = '20-second attempt deadline exceeded'
                elif sum((directory / name).stat().st_size for name in ('stdout.json', 'stderr.log')) > 64 * 1024**2:
                    failure = '64-MiB output budget exceeded'
                if failure:
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                time.sleep(0.025)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
    elapsed = time.monotonic() - start
    if elapsed > 20:
        failure = failure or '20-second attempt deadline exceeded'
    detail = (directory / 'stderr.log').read_text(errors='replace')[-4000:]
    result = dict(returncode=process.returncode, seconds=elapsed, sampled_peak_rss_bytes=peak,
                  memory_measurement='25-ms RSS samples; not a peak-allocation proof',
                  budget_failure=failure, diagnostic=detail)
    value = None
    if process.returncode == 0 and not failure:
        value = json.loads((directory / 'stdout.json').read_text())
    return result, value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--air-input-dir', required=True, type=Path)
    parser.add_argument('--compiler-build', type=Path, default=ROOT / 'build/gpu-001/compiler')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/gpu-001/translation')
    parser.add_argument('--profile', type=Path, default=ROOT / '.cache/gpu-reference/metal2vulkan/crates/metal2vulkan-validation/profiles/vk12-bare.json')
    parser.add_argument('--compile-entrypoints', action='store_true')
    parser.add_argument('--vertex-descriptor', type=Path,
                        help='Explicit diagnostic layout, not an observed system pipeline')
    parser.add_argument('--color-attachments', type=Path,
                        help='Explicit attachment-index/pixel-format map for paired pipelines')
    parser.add_argument('--require-fragment-output', action='store_true',
                        help='Reject validation-only empty fragments in selected pipeline checks')
    parser.add_argument('--pipeline', action='append', default=[], metavar='LIB:INDEX:LIB:INDEX')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit('Use a fresh output directory; never reuse an earlier success report')
    build = json.loads((args.compiler_build / 'build-report.json').read_text())
    binary = Path(build['binary'])
    if build['translator_revision'] != SOURCE_PIN or sha(binary) != build['binary_sha256'] or \
            sha(ROOT / 'drivers/AdrenoMetal/tools/MetalVulkanProbe.rs') != build['source_sha256']:
        raise SystemExit('Compiler/source identity differs from its build report')
    validator = shutil.which('spirv-val')
    if not validator:
        raise SystemExit('spirv-val is required; translation alone cannot pass validation')
    inventory_path = args.air_input_dir / 'target-inputs.json'
    if sha(inventory_path) != INVENTORY_PIN:
        raise SystemExit('Target AIR audit differs from the pinned original inventory')
    audit = json.loads(inventory_path.read_text())
    recorded = {Path(x['file']).parts[-2].removesuffix('.framework'): x['sha256'] for x in audit['inputs']}
    if recorded != LIBRARIES or len(audit['modules']) != 240:
        raise SystemExit('Only the existing 240-module iPad7,1 target inventory is accepted')
    modules = {(m['library'], m['index']): m for m in audit['modules']}
    if len(modules) != 240:
        raise SystemExit('Duplicate module identity')

    def source(module):
        p = args.air_input_dir / module['library'] / f'module-{module["index"]}.bc'
        if sha(p) != module['bitcode_sha256']:
            raise ValueError('Original AIR differs from inventory')
        return p

    # Verify every source before creating any result.
    for module in modules.values():
        source(module)
    output.mkdir(parents=True)
    cases = output / 'cases'
    cases.mkdir()
    parsed = []
    compiled = []
    unexpected = []
    for key, module in modules.items():
        tag = f'{key[0]}-{key[1]}'
        result, value = worker([binary, '--list', source(module)], cases / ('parse-' + tag))
        result.update(library=key[0], index=key[1], input_sha256=module['bitcode_sha256'])
        if value is not None:
            result['functions'] = value['functions']
            if not any(f['name'] == module['name'] for f in value['functions']):
                unexpected.append('Original function absent from parsed module: ' + tag)
        elif result['returncode'] != 2 or result['budget_failure']:
            unexpected.append('Parser failure: ' + tag)
        parsed.append(result)

    jobs = []
    if args.compile_entrypoints:
        jobs.extend(([m], f'{k[0]}-{k[1]}') for k, m in modules.items() if m['stage'] in ('kernel', 'vertex'))
    for item in args.pipeline:
        a, i, b, j = item.split(':')
        jobs.append(([modules[(a, int(i))], modules[(b, int(j))]], item.replace(':', '-')))
    for members, tag in jobs:
        attempt_start = time.monotonic()
        command = [binary]
        if args.vertex_descriptor:
            command.extend(['--vertex-descriptor', args.vertex_descriptor])
        if args.color_attachments:
            command.extend(['--color-attachments', args.color_attachments])
        command.append(args.profile)
        for member in members:
            command.extend([source(member), member['name']])
        case = cases / ('compile-' + tag)
        result, value = worker(command, case)
        result['inputs'] = [{k: m[k] for k in ('library', 'index', 'bitcode_sha256')} for m in members]
        if value is not None:
            result['artifact'] = value
            for index, stage in enumerate(value['stages']):
                words = stage.pop('spirv')
                if len(words) < 5 or words[0] != 0x07230203:
                    raise ValueError('Invalid SPIR-V header from translator')
                stage.update(output_stores(words))
                if args.require_fragment_output and stage['stage'] == 'VK_SHADER_STAGE_FRAGMENT_BIT' and not stage['output_store_instructions']:
                    unexpected.append('Fragment has no output-store instructions: ' + tag)
                data = struct.pack('<' + 'I' * len(words), *words)
                path = case / f'stage-{index}.spv'
                path.write_bytes(data)
                stage.update(bytes=len(data), sha256=sha(path), validation=[])
                for env in value['validation_envs']:
                    remaining = 20 - (time.monotonic() - attempt_start)
                    if remaining <= 0:
                        result['budget_failure'] = '20-second translation/validation deadline exceeded'
                        unexpected.append('Attempt deadline exceeded: ' + tag)
                        break
                    try:
                        validation = subprocess.run([validator, '--target-env', env,
                                                     *value['validation_relaxations'], str(path)],
                                                    capture_output=True, text=True, timeout=remaining)
                    except subprocess.TimeoutExpired:
                        result['budget_failure'] = '20-second translation/validation deadline exceeded'
                        unexpected.append('Validation deadline exceeded: ' + tag)
                        break
                    stage['validation'].append(dict(environment=env, returncode=validation.returncode,
                                                    diagnostic=validation.stderr[-4000:]))
                    if validation.returncode:
                        unexpected.append('SPIR-V validation failed: ' + tag)
            (case / 'stdout.json').unlink()
            result['semantic_equivalence_qualified'] = False
        elif result['returncode'] != 2 or result['budget_failure']:
            unexpected.append('Compiler failure: ' + tag)
        compiled.append(result)
        result['translation_and_validation_seconds'] = time.monotonic() - attempt_start
    for module in modules.values():
        source(module)
    report = dict(compiler=build, input_inventory_sha256=sha(inventory_path), profile_sha256=sha(args.profile),
                  vertex_descriptor_sha256=sha(args.vertex_descriptor) if args.vertex_descriptor else None,
                  color_attachments_sha256=sha(args.color_attachments) if args.color_attachments else None,
                  profile_scope='synthetic Vulkan minimum; not observed Adreno capabilities',
                  validator_version=subprocess.check_output([validator, '--version'], text=True).strip(),
                  validator_sha256=sha(Path(validator).resolve()), parse_results=parsed, compile_results=compiled,
                  parse_counts=dict(Counter(str(x['returncode']) for x in parsed)),
                  compile_counts=dict(Counter(str(x['returncode']) for x in compiled)),
                  unexpected_failures=unexpected, original_inputs_unchanged=True,
                  gpu_execution=False, active_gpu_smmu_4k_qualified=False, deployment_ready=False)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('parse_counts', 'compile_counts', 'unexpected_failures', 'deployment_ready')}))
    return bool(unexpected)


if __name__ == '__main__':
    raise SystemExit(main())
