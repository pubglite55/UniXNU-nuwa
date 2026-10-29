#!/usr/bin/env python3
"""Compile upstream XNU granule constants; this is not a kernel build."""
import json
from pathlib import Path
import shutil
import struct
import subprocess

source = Path('refer/xnu')
output = Path('build/xnu-granules')
output.mkdir(parents=True, exist_ok=True)
compiler = shutil.which('clang')
profiles = [('BCM2837', 12, 0, 2), ('VMAPPLE', 14, 2, 1)]
results = {}
for profile, shift, tg0, tg1 in profiles:
    text = ('#include <pexpert/arm64/board_config.h>\n'
            '#include <arm64/proc_reg.h>\n'
            f'.if ARM_PGSHIFT != {shift}\n.error "page shift"\n.endif\n'
            f'.if ((TCR_EL1_BOOT >> 14) & 3) != {tg0}\n.error "TG0"\n.endif\n'
            f'.if ((TCR_EL1_BOOT >> 30) & 3) != {tg1}\n.error "TG1"\n.endif\n'
            '.data\n.quad TCR_EL1_BOOT\n.quad ARM_PGBYTES\n')
    path = output / f'{profile}.S'
    path.write_text(text)
    command = [compiler, '--target=aarch64-none-elf', '-D__arm64__=1',
               '-DASSEMBLER', '-D__ASSEMBLER__', f'-DARM64_BOARD_CONFIG_{profile}', '-ffreestanding',
               '-Werror', '-c', '-I', str(source / 'osfmk'),
               '-I', str(source / 'pexpert'), '-I', str(source / 'EXTERNAL_HEADERS'),
               str(path), '-o', str(output / f'{profile}.o')]
    subprocess.run(command, check=True)
    binary = output / f'{profile}.bin'
    subprocess.run([shutil.which('llvm-objcopy'), '--dump-section', f'.data={binary}',
                    str(output / f'{profile}.o')], check=True)
    tcr, page = struct.unpack('<QQ', binary.read_bytes())
    results[profile] = {'boot_tcr': tcr, 'page_bytes': page}
    print(f'{profile}: page size {page}, TCR {tcr:#x}, TG0={tg0}, TG1={tg1}')
(output / 'constants.json').write_text(json.dumps(results, indent=2) + '\n')
