#!/usr/bin/env python3
"""Check real Darwin panic argument bridges and patch coverage without a VM/device.

The native host executes only the two assembly argument adapters, against the
actual source wrapper bodies and a host text collector. Privileged rendering,
kernel faults, hardware display and the cause of any physical stall are not
qualified by this test.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--kernel', type=Path, required=True)
p.add_argument('--output', type=Path, default=ROOT/'build/panic-entry-coverage')
args = p.parse_args()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=True)
(out/'report.json').unlink(missing_ok=True)
assert platform.system() == 'Darwin' and platform.machine() == 'arm64', 'Darwin ARM64 host required for the actual argument ABI'


def run(cmd, **kw):
    return subprocess.check_output([str(x) for x in cmd], text=True, timeout=90, **kw)


def function_body(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


original = (ROOT/'refer/xnu/osfmk/kern/debug.c').read_text()
header = (ROOT/'refer/xnu/osfmk/kern/debug.h').read_text()
assert re.search(r'#define DEBUGGER_INTERNAL_OPTION_THREAD_BACKTRACE\s+0x200ULL', header)
assert re.search(r'#define DEBUGGER_INTERNAL_OPTIONS_MASK\s+\(DEBUGGER_INTERNAL_OPTION_THREAD_BACKTRACE\)', header)
wrappers = [function_body(original, '\nvoid\n'+name+'(')
            for name in ('panic', 'panic_with_options', 'panic_with_data')]
renderer = (ROOT/'scripts/xnu-panic-screen.c').read_text()
direct = function_body(renderer, 'void panic_screen (')
common = function_body(renderer, 'void panic_screen_common (')
direct_asm = direct[direct.index('__asm__'):direct.rindex(';')+1].replace('panic_screen_main', '_collect_arguments')
common_asm = common[common.index('__asm__'):common.rindex(';')+1].replace('panic_screen_main', '_collect_arguments')
fixture = r'''
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned char uuid_t[16];
_Static_assert(sizeof(va_list) == sizeof(char *), "Darwin ARM64 stack argument pointer");
#define DEBUGGER_INTERNAL_OPTION_THREAD_BACKTRACE 0x200ULL
#define DEBUGGER_INTERNAL_OPTIONS_MASK (DEBUGGER_INTERNAL_OPTION_THREAD_BACKTRACE)
static char collected[256];
static unsigned records, data_calls;
__attribute__((used,noinline)) void collect_arguments(const char *fmt,const unsigned long *slots) {
 va_list ap=(char *)slots;
 vsnprintf(collected,sizeof(collected),fmt,ap);++records;
}
static void ext_paniclog_panic_with_data(uuid_t uuid,void *addr,uint32_t length) {
 assert(uuid[0]==0x5a && addr && length==7);++data_calls;
}
'''
fixture += '\n__attribute__((naked,noinline)) void panic_trap_to_debugger(const char *fmt,va_list *ap,unsigned reason,void *ctx,uint64_t options,void *data,unsigned long caller) {'+common_asm+'}\n'
fixture += '\n__attribute__((naked,noinline)) void direct_entry(const char *fmt,...) {'+direct_asm+'}\n'
fixture += '\n'.join(wrappers).replace('\npanic(', '\nfixture_panic(').replace('\npanic_with_options(', '\nfixture_panic_with_options(').replace('\npanic_with_data(', '\nfixture_panic_with_data(')
fixture += r'''
int main(void) {
 direct_entry("direct %s %u %llx", "argument", 37U, 0x123456789abcdef0ULL);
 assert(!strcmp(collected,"direct argument 37 123456789abcdef0"));
 fixture_panic("plain %s %u %llx", "argument", 41U, 0xfedcba9876543210ULL);
 assert(!strcmp(collected,"plain argument 41 fedcba9876543210"));
 fixture_panic_with_options(9,(void *)0x1234,0x240,"options %s %u %llx", "argument", 43U, 0x100000001ULL);
 assert(!strcmp(collected,"options argument 43 100000001"));
 uuid_t uuid={0x5a};char data[7]={0};
 fixture_panic_with_data(uuid,data,sizeof(data),"data %s %u %llx", "argument", 47U, 0x1122334455667788ULL);
 assert(!strcmp(collected,"data argument 47 1122334455667788"));
 assert(records==4 && data_calls==1);
 puts("PASS: actual Darwin ARM64 argument adapters, direct entry and all three source panic wrappers");
}
'''
(out/'abi.c').write_text(fixture)
run(['clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-parameter',out/'abi.c','-o',out/'abi'])
print(run([out/'abi']), end='')

spec = importlib.util.spec_from_file_location('panic_probe', ROOT/'scripts/patch-xnu-entry-probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
before = args.kernel.read_bytes()
probe.load_segments(before)
names = probe.rebase(args.kernel, before)
expected_vinfo=names.get('_boot_progress_panic_vinfo',names.get('_vinfo'))
assert expected_vinfo is not None and probe.VINFO_VA==expected_vinfo, 'Wrong panic mapping prefix'
symbols = probe.kernel_symbols(args.kernel)
starts = sorted(symbols)


def calls(name):
    low, high = probe.function_range(symbols, name)
    result = []
    for va in range(low, high, 4):
        word = struct.unpack_from('<I', before, probe.file_offset(va))[0]
        if word >> 26 == 0b100101:
            n = word & 0x3ffffff
            n -= (1 << 26) if n & (1 << 25) else 0
            result.append(va+n*4)
    return result


for name in ('_panic', '_panic_with_options', '_panic_with_data'):
    assert names['_panic_trap_to_debugger'] in calls(name), name+' does not use the expected real common funnel'

env = dict(os.environ)
env['PATH'] = '/opt/homebrew/opt/llvm/bin:/opt/homebrew/opt/lld/bin:' + env['PATH']
with tempfile.TemporaryDirectory(dir=out) as temp:
    temp = Path(temp)
    copy = temp/'candidate.macho'
    shutil.copyfile(args.kernel, copy)
    log = run(['python3',ROOT/'scripts/patch-xnu-entry-probe.py',copy,'--panic-screen','--no-reset'],env=env,cwd=ROOT)
    (out/'patch.log').write_text(log)
    after = copy.read_bytes()
    common_site = names['_panic_trap_to_debugger']
    panic_cave = probe.CAVES[2]+probe.CAVE_SIZE
    code, load, entry = probe.assemble_c(ROOT/'scripts/xnu-panic-screen.c',panic_cave,temp,names)
    alternate = probe.panic_common_entry(temp,code,load)
    assert load+len(code) <= probe.PANIC_CAVE_END
    for site, target in [(probe.PANIC_VA,entry),(common_site,alternate)]:
        assert struct.unpack_from('<I',after,probe.file_offset(site))[0] == probe.branch(site,target)
    # The other wrappers must remain byte-identical. They reach the newly
    # covered shared entry through their genuine original call instructions.
    for name in ('_panic_with_options','_panic_with_data'):
        low, high = probe.function_range(symbols,name)
        at=probe.file_offset(low)
        assert before[at:at+high-low] == after[at:at+high-low]
    allowed=[(probe.ENTRY_VA,4),(probe.MMU_ENABLE_VA,4),(probe.PANIC_VA,4),(common_site,4),
             (probe.CAVES[1],probe.CAVE_SIZE),(probe.CAVES[2],probe.CAVE_SIZE),
             (load,len(code))]
    # Check every other byte, including the unchanged original prelinked code.
    allowed=sorted((probe.file_offset(va),probe.file_offset(va)+size) for va,size in allowed)
    cursor=0
    for low,high in allowed:
        assert before[cursor:low] == after[cursor:low], 'Unexpected non-probe mutation'
        cursor=high
    assert before[cursor:] == after[cursor:] and len(before)==len(after)
    report=dict(passed=True,source_kernel_sha256=hashlib.sha256(before).hexdigest(),
                patched_copy_sha256=hashlib.sha256(after).hexdigest(),
                source_wrappers=['panic','panic_with_options','panic_with_data'],
                native_host_adapter_execution=True,common_site=hex(common_site),
                renderer_bytes=len(code),renderer_capacity=probe.PANIC_CAVE_END-load,
                only_declared_probe_regions_changed=True,qemu_execution=False,
                device_operation=False,hardware_panic_rendering_verified=False,
                physical_stall_root_cause_established=False)
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: actual linked wrappers, both patched entries, bounded renderer and full-image mutation boundaries; no device or VM execution')
