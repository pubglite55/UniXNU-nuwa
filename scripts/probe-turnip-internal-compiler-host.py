#!/usr/bin/env python3
"""Count real IR3 backend entries hidden below public pipeline cache feedback.

Unchanged actual host Turnip plus the mandatory software transport. LLDB stops
at entries and immediately resumes; no shader executes and timing is unqualified.
The canonical driver, original inputs and prior qualified packs stay unchanged.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, reason):
    if not condition:
        raise SystemExit(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--qualification', type=Path, required=True,
                        help='Exact passing check-priming-cache-host output directory')
    args = parser.parse_args()
    output, qualification = args.output.resolve(), args.qualification.resolve()
    require(not output.exists(), 'Preserve existing evidence; choose a fresh directory')
    require(shutil.disk_usage(ROOT).free > 5 * 1024**3 + 32 * 1024**2, 'Preserve 5 GiB and bounded logs')
    previous_path = qualification / 'checkpoint.json'
    previous = json.loads(previous_path.read_text())
    paths = dict(program='build/priming-cache/priming_cache_host',
                 driver='build/mesa-tu/src/freedreno/vulkan/libvulkan_freedreno.dylib',
                 peer='build/turnip-darwin-host/libhostiokit.dylib',
                 loader='build/priming-cache/libOfflinePrimingCacheControl.dylib')
    # This is an additional observation of an exact previously qualified pair.
    # Never silently use a newly rebuilt compiler, wrapper or executable.
    for name, digest in previous['sources_sha256'].items():
        require(sha(ROOT / name) == digest, 'Exact qualified source: ' + name)
    require(sha(ROOT / paths['driver']) == previous['driver_sha256'], 'Exact previously qualified host compiler')
    for name, digest in previous['runtime_patches_sha256'].items():
        require(sha(ROOT / 'drivers/AdrenoMetal/bridge/patches' / name) == digest, 'Exact qualified runtime patch: ' + name)
    for name, field in [('program', 'process_sha256'), ('peer', 'peer_sha256'), ('loader', 'loader_sha256')]:
        require(sha(ROOT / paths[name]) == previous[field], 'Exact qualified binary: ' + name)
    require(sha(ROOT / 'build/adreno-metal-bridge/host/libadreno_metal_bridge.a') == previous['host_bridge_sha256'], 'Exact linked runtime input')
    output.mkdir(parents=True)
    identities = {name: sha(ROOT / path) for name, path in paths.items()}
    cases = {}
    cache = output / 'cache'
    produced = None
    for mode in ('cold-miss', 'produce', 'consume'):
        work = output / mode
        work.mkdir()
        config = dict(root=str(ROOT), work=str(work), cache=str(cache), mode=mode, **paths)
        config_path = work / 'config.json'
        config_path.write_text(json.dumps(config, indent=2) + '\n')
        commands = work / 'commands.lldb'
        commands.write_text('command script import ' + shlex.quote(str(ROOT / 'scripts/turnip_compiler_lldb.py')) +
                            '\nscript turnip_compiler_lldb.run(lldb.debugger)\n')
        env = dict(os.environ, NMB_OFFLINE_COMPILER_CONFIG=str(config_path))
        run = subprocess.run(['xcrun', 'lldb', '--batch', '--source', str(commands)],
                             capture_output=True, text=True, env=env, timeout=60)
        (work / 'debugger.log').write_text(run.stdout + run.stderr)
        require(run.returncode == 0, 'Bounded own debugger failed: ' + mode)
        trace_path = work / 'trace.json'
        trace = json.loads(trace_path.read_text())
        require(trace['launch_success'] and trace['exited'] and trace['exit_status'] == 0 and
                trace['breakpoint_locations'] == 1 and not trace['trace_overflow'], 'Actual complete compiler trace: ' + mode)
        text = (work / 'worker.stdout').read_text()
        pattern = (r'^PASS: device priming ' + mode + r' pid=\d+ compute=(\d+)/(\d+)/(\d+)/(\d+)/(\d+) '
                   r'graphics=(\d+)/(\d+)/(\d+)/(\d+)/(\d+) uuid_mutations=0 submissions=1 live=0; software peer, no shader execution$')
        row = re.search(pattern, text, re.M)
        require(row, 'Complete actual worker feedback: ' + mode)
        c, g = tuple(map(int, row.groups()[:5])), tuple(map(int, row.groups()[5:]))
        require((c, g) == (((1, 0, 1, 0, 0), (0, 0, 0, 0, 0)) if mode == 'cold-miss' else
                          ((1, 1, 0, 1, int(mode == 'consume')), (1, 1, 0, 1, int(mode == 'consume')))),
                'Actual empty refusal/producer/strict-consumer feedback: ' + mode)
        counts = Counter(entry['scope'] for entry in trace['rows'])
        require(counts['clear-blit'] == 18 and counts['empty'] == 2, 'Exact observed internal startup compiler calls')
        require(all(entry['stack'][0] == 'ir3_compile_shader_nir' and
                    any('tu_CreateDevice(' in s for s in entry['stack']) for entry in trace['rows'] if entry['scope'] != 'other'),
                'Actual IR3 entries occur inside original device initialization')
        require(counts['other'] == 0 if mode != 'produce' else counts['other'] > 0,
                'Strict public-pipeline refusal/hits distinguish actual helper backend compilation')
        records = {str(p.relative_to(cache)): dict(bytes=p.stat().st_size, sha256=sha(p))
                   for p in cache.rglob('*') if p.is_file()}
        if mode == 'cold-miss':
            require(not records, 'Cold refusal never writes a successful helper cache')
        elif mode == 'produce':
            require(len(records) == 1, 'Exactly one bounded own priming record')
            produced = records
        else:
            require(records == produced, 'Strict consumer leaves every producer-cache byte unchanged')
        cases[mode] = dict(compiler_entries=len(trace['rows']), scopes=dict(counts), compute=c, graphics=g,
                           trace_sha256=sha(trace_path), worker_stdout_sha256=sha(work / 'worker.stdout'))
        print(mode, dict(counts), flush=True)
    require(identities == {name: sha(ROOT / path) for name, path in paths.items()}, 'Canonical compiler/fixture binaries unchanged')
    report = dict(evidence='actual host Turnip IR3 backend entries under LLDB; software peer executes no shader',
                  qualification_sha256=sha(previous_path), identities=identities, cases=cases, cache_manifest=produced,
                  checker_sha256=sha(Path(__file__)), callbacks_sha256=sha(ROOT / 'scripts/turnip_compiler_lldb.py'),
                  mesa_base_revision=subprocess.check_output(['git', '-C', ROOT / '.cache/mesa-work', 'rev-parse', 'HEAD'], text=True).strip(),
                  patches_sha256={p: sha(ROOT / p) for p in json.loads((ROOT / 'scripts/data/adreno-compiler-inputs.json').read_text())['patches']},
                  timing_qualified=False, shader_execution=False, physical_device_tested=False,
                  active_native_adreno_4k=False, hardware_ready=False, stable_120_fps_qualified=False)
    (output / 'checkpoint.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: real internal compilation persists despite strict public-pipeline hits; no timing/hardware qualification')


if __name__ == '__main__':
    main()
