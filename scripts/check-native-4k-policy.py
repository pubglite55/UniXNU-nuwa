#!/usr/bin/env python3
"""Execute XNU's actual page-size policy at RAM boundaries, without a VM."""
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / '.cache/xnu-work/osfmk/arm/arm_init.c').read_text()
start = source.index('\t\t/* Native non-Apple 4K builds expose the hardware page size at any RAM size. */')
end = source.index('#ifdef  APPLETYPHOON', start)
policy = source[start:end]
output = ROOT / 'build/xnu/native-4k-policy'
output.mkdir(parents=True, exist_ok=True)
program = output / 'policy.c'
program.write_text('''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define PAGE_MAX_SHIFT 14
int PAGE_SHIFT_CONST;
unsigned int page_shift_user32;
static void policy(uint64_t memory) {
  struct { uint64_t memSize; } value = { memory }, *args = &value;
  (void)args;
''' + policy + '''
}
int main(int argc, char **argv) {
  if (argc != 2) return 1;
  policy(strtoull(argv[1], 0, 0));
  printf("%d %u\\n", PAGE_SHIFT_CONST, page_shift_user32);
  return 0;
}
''')
cases = [0x10000000, 0x40000000, 0x40001000, 0x80000000, 0x200000000]
report = {}
profiles = [('native-4k', ['-DARM_PGSHIFT=12'], False, False),
            ('apple-16k-control', ['-DARM_PGSHIFT=14', '-D__ARM_16K_PG__=1', '-DAPPLE_ARM64_ARCH_FAMILY=1'], True, False),
            ('apple-4k-control', ['-DARM_PGSHIFT=12', '-DAPPLE_ARM64_ARCH_FAMILY=1'], False, True)]
for name, flags, sixteen, apple_four in profiles:
    executable = output / name
    subprocess.run([shutil.which('clang'), '-Wall', '-Wextra', '-Werror', *flags,
                    str(program), '-o', str(executable)], check=True)
    values = []
    for memory in cases:
        actual = tuple(map(int, subprocess.check_output([executable, hex(memory)], text=True).split()))
        expected = ((14, 14) if sixteen else ((14 if memory > 0x40000000 else 12), 14)
                    if apple_four else (12, 12))
        if actual != expected:
            raise SystemExit(f'{name}, RAM={memory:#x}: got {actual}, expected {expected}')
        values.append({'ram': hex(memory), 'kernel_shift': actual[0], 'user32_shift': actual[1]})
    report[name] = values
    print(f'{name}: {len(cases)} RAM boundaries pass')
report['scope'] = 'Host execution of the actual extracted arm_init policy; not an iPadOS userspace test'
(output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
