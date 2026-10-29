# SPDX-License-Identifier: MIT
"""Bounded debugger callbacks for the own host-only compiler probe.

No patched instruction, changed argument, forced return, hardware connection,
or shader execution. Breakpoints perturb timing; only invocation counts qualify.
"""
import json
import os
from pathlib import Path
import lldb

ROWS = []
LIMIT = 256


def entered(frame, location, internal_dict):
    if len(ROWS) == LIMIT:
        return True
    thread = frame.GetThread()
    stack = [thread.GetFrameAtIndex(i).GetFunctionName() or '?'
             for i in range(min(thread.GetNumFrames(), 32))]
    scope = ('clear-blit' if any('tu_init_clear_blit_shaders' in s for s in stack)
             else 'empty' if any('tu_init_empty_shaders' in s for s in stack)
             else 'other')
    ROWS.append(dict(scope=scope, stack=stack))
    return False


def run(debugger):
    config = json.loads(Path(os.environ['NMB_OFFLINE_COMPILER_CONFIG']).read_text())
    root, work = Path(config['root']), Path(config['work'])
    debugger.SetAsync(False)
    target = debugger.CreateTarget(str(root / config['program']))
    breakpoint = target.BreakpointCreateByName('ir3_compile_shader_nir', 'libvulkan_freedreno.dylib')
    breakpoint.SetScriptCallbackFunction(__name__ + '.entered')
    launch = lldb.SBLaunchInfo([str(root / config['driver']), config['cache'], config['mode']])
    environment = {k: v for k, v in os.environ.items() if not k.startswith(
        ('IR3_', 'FD_MESA_', 'NIR_', 'TU_', 'HOSTSIM_', 'MESA_', 'NMB_TEST_'))}
    environment.update(DYLD_INSERT_LIBRARIES=str(root / config['peer']),
                       NMB_TEST_PRIMING_CACHE_LOADER=str(root / config['loader']))
    launch.SetEnvironmentEntries([k + '=' + v for k, v in environment.items()], True)
    launch.AddOpenFileAction(1, str(work / 'worker.stdout'), False, True)
    launch.AddOpenFileAction(2, str(work / 'worker.stderr'), False, True)
    error = lldb.SBError()
    process = target.Launch(launch, error)
    exited = process.GetState() == lldb.eStateExited
    result = dict(launch_success=error.Success(), exited=exited,
                  exit_status=process.GetExitStatus() if exited else None,
                  breakpoint_locations=breakpoint.GetNumLocations(),
                  rows=ROWS, trace_limit=LIMIT, trace_overflow=len(ROWS) == LIMIT,
                  timing_qualified=False, physical_device_tested=False, shader_execution=False)
    if not exited:
        process.Kill()
    (work / 'trace.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Recorded %d actual backend entries; timing is unqualified' % len(ROWS))
