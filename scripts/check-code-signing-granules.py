#!/usr/bin/env python3
"""Compile the actual XNU CodeDirectory page-size gate as a bounded host probe."""
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / '.cache/xnu-work/bsd/kern/ubc_subr.c').read_text()
body = source[source.index('cs_validate_codedirectory(const CS_CodeDirectory *cd, size_t length)'):]
match = re.search(r'\tif \(\(cd->pageSize != PAGE_SHIFT_4K\).*?\n\t\}', body, re.S)
if not match:
    raise SystemExit('Cannot isolate the actual CodeDirectory page-size gate')
out = ROOT / 'build/target-userspace'
out.mkdir(parents=True, exist_ok=True)
program = out / 'codesign-granule-gate.c'
program.write_text('''#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define PAGE_SHIFT_4K 12
static int native_kernel_shift = NATIVE_TEST_PAGE_SHIFT;
#define PAGE_SHIFT native_kernel_shift
struct directory_probe { uint8_t pageSize; };
int main(int argc, char **argv) {
 if (argc != 2) return 2;
 const struct directory_probe value = { .pageSize = (uint8_t)strtoul(argv[1], NULL, 10) };
 const struct directory_probe *cd = &value;
''' + match[0] + '\n return 0;\n}\n')
observed = []
for cache_mode in (0, 1):
    for kernel_shift in (12, 14):
        binary = out / f'codesign-granule-{kernel_shift}-cache-{cache_mode}'
        subprocess.run(['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        f'-DNATIVE_TEST_PAGE_SHIFT={kernel_shift}', f'-DXNU_NATIVE_CS_HASH_CACHE={cache_mode}',
                        program, '-o', binary], check=True)
        for signature_shift in (12, 14):
            result = subprocess.run([binary, str(signature_shift)], capture_output=True, text=True)
            accepted = result.returncode == 0
            expected = signature_shift == 12 or kernel_shift == 14 or cache_mode == 1
            if accepted != expected:
                raise SystemExit('Unexpected behavior in the actual XNU page-size gate')
            observed.append({'kernel_page_shift': kernel_shift, 'signature_hash_shift': signature_shift,
                             'native_integrity_cache_enabled': bool(cache_mode),
                             'accepted_by_actual_source_gate': accepted, 'exit_status': result.returncode})
(out / 'codesign-granule-gate.json').write_text(json.dumps({
    'source': 'Darwin 23 ubc_subr.c / cs_validate_codedirectory page-size gate only',
    'host_probe': True, 'complete_kernel_signature_validator_exercised': False, 'cases': observed}, indent=2) + '\n')
print('PASS: eight compiled actual gate cases distinguish native integrity-cache opt-in and original refusal behavior')
print('Gate acceptance is not complete integrity validation; no hardware page tables are changed by this host probe')
