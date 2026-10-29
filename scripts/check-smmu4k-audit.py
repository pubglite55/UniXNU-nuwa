#!/usr/bin/env python3
"""Bounded physical-graph audit qualification; host buffers are not hardware."""
import hashlib,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
kit=ROOT/'kits/ArmSmmu4K';out=ROOT/'build/arm-smmu-4k-audit'
out.mkdir(parents=True,exist_ok=True);(out/'report.json').unlink(missing_ok=True)
sources=[kit/(name+'.c') for name in ['ArmSmmu4K','ArmSmmu4KContext','ArmSmmu4KProgram','ArmSmmu4KAudit','ArmSmmu4KTableMemory']]
test=out/'test-audit'
subprocess.run(['xcrun','clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',*sources,kit/'test_audit.c','-o',test],check=True,timeout=60)
run=subprocess.run([test],capture_output=True,text=True,timeout=60)
print(run.stdout,end='')
if run.returncode:raise SystemExit(run.stderr)
counts=re.search(r'(\d+) physical-graph profiles, (\d+) descriptor mutations, (\d+) read failures',run.stdout)
if not counts:raise SystemExit('Missing actual audit coverage')
(out/'host.log').write_text(run.stdout)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
inputs=sources+[s.with_suffix('.h') for s in sources]+[kit/'test_audit.c',Path(__file__)]
(out/'report.json').write_text(json.dumps(dict(passed=True,sources={str(p.relative_to(ROOT)):sha(p) for p in inputs},
 profiles=int(counts[1]),descriptor_mutations=int(counts[2]),physical_read_failures=int(counts[3]),
 host_asan_ubsan=True,all_reachable_slots_audited=True,physical_graph_not_rebuilt=True,
 relocated_owned_tables=True,cross_region_full_pool_checks=True,actual_volatile_adapter_on_host_buffers=True,
 physical_labels_synthetic=True,actual_hardware_tables_observed=False,gpu_execution_qualified=False),indent=2)+'\n')
print('PASS: bounded physical graph, real volatile-load adapter on host buffers; active-context integration/native ABI checked by check-sheng-gpu-smmu.py')
