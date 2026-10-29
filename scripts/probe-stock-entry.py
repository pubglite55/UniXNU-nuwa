#!/usr/bin/env python3
"""Observe the first exception from an unchanged Mach-O on QEMU virt.

This tests the instruction entry boundary, not an XNU platform or OS boot.
The fixture supplies skeletal boot arguments and an optional test device tree.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
PHYS_BASE = 0x50000000
BOOT_ARGS_PA = 0x5ff00000


def prepare(kernel, output, phys_base=PHYS_BASE, boot_args_pa=BOOT_ARGS_PA, device_tree=None,
            command_line='-v serial=3 debug=0x14e'):
    data = kernel.read_bytes()
    if data[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('Expected decompressed little-endian 64-bit Mach-O')
    cpu, subtype, kind, count, commands = struct.unpack_from('<IIIII', data, 4)
    if cpu != 0x100000c or kind != 2 or commands > len(data) - 32:
        raise ValueError('Expected AArch64 MH_EXECUTE with complete load commands')
    offset = 32
    segments = []
    entry = None
    for _ in range(count):
        if offset + 8 > 32 + commands:
            raise ValueError('Truncated Mach-O command')
        command, size = struct.unpack_from('<II', data, offset)
        if size < 8 or offset + size > 32 + commands:
            raise ValueError('Invalid Mach-O command size')
        if command == 0x19:
            if size < 72:
                raise ValueError('Truncated LC_SEGMENT_64')
            name, address, length, fileoff, filesize = struct.unpack_from('<16sQQQQ', data, offset + 8)
            if filesize > length or fileoff + filesize > len(data):
                raise ValueError('Invalid segment file extent')
            if length:
                segments.append((name.rstrip(b'\0').decode(), address, length, fileoff, filesize))
        elif command == 5:
            if size != 288 or struct.unpack_from('<II', data, offset + 8) != (6, 68):
                raise ValueError('Unsupported LC_UNIXTHREAD flavor')
            entry = struct.unpack_from('<Q', data, offset + 272)[0]
        offset += size
    if offset != 32 + commands or not segments or entry is None:
        raise ValueError('Missing Mach-O entry or inconsistent command extent')
    segments.sort(key=lambda s: s[1])
    for left, right in zip(segments, segments[1:]):
        if left[1] + left[2] > right[1]:
            raise ValueError('Overlapping virtual segments')
    base = segments[0][1]
    end = max(s[1] + s[2] for s in segments)
    if not 0x40000000 <= phys_base < boot_args_pa or phys_base % 4096:
        raise ValueError('Physical base must be page-aligned in the fixture RAM')
    if boot_args_pa % 4096 or boot_args_pa + 0x4000 > 0x60000000:
        raise ValueError('Boot arguments must be page-aligned in fixture RAM')
    if end - base > boot_args_pa - phys_base or not base <= entry < end:
        raise ValueError('Kernel does not fit the fixed test memory layout')
    image = bytearray(end - base)
    for name, address, length, fileoff, filesize in segments:
        image[address - base:address - base + filesize] = data[fileoff:fileoff + filesize]
    (output / 'kernel-flat.bin').write_bytes(image)
    boot = bytearray(0x4000)
    struct.pack_into('<HH4xQQQQ', boot, 0, 2, 2, base, phys_base,
                     0x60000000 - phys_base, boot_args_pa + len(boot))
    encoded_command_line = command_line.encode('ascii')
    if len(encoded_command_line) >= 1024:
        raise ValueError('Command line exceeds boot_args capacity')
    boot[0x6c:0x6c + len(encoded_command_line)] = encoded_command_line
    struct.pack_into('<Q', boot, 0x478, 0x60000000 - phys_base)
    if device_tree:
        tree = device_tree.read_bytes()
        if len(tree) > len(boot) - 0x1000:
            raise ValueError('Test device tree exceeds reserved boot buffer')
        boot[0x1000:0x1000 + len(tree)] = tree
        struct.pack_into('<QI', boot, 0x60, base + boot_args_pa + 0x1000 - phys_base, len(tree))
    (output / 'boot-args.bin').write_bytes(boot)
    return {'sha256': hashlib.sha256(data).hexdigest(), 'cpu_subtype': subtype,
            'virtual_base': hex(base), 'physical_base': hex(phys_base),
            'boot_args_pa': hex(boot_args_pa), 'entry_va': hex(entry),
            'command_line': command_line,
            'device_tree_sha256': hashlib.sha256(tree).hexdigest() if device_tree else None,
            'entry_pa': hex(phys_base + entry - base), 'mapped_bytes': len(image),
            'segments': [{'name': s[0], 'va': hex(s[1]), 'size': s[2]} for s in segments]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel', type=Path)
    parser.add_argument('--cpu', default='cortex-a710')
    parser.add_argument('--timeout', type=float, default=5)
    parser.add_argument('--output', type=Path, default=ROOT / 'build' / 'stock-entry')
    parser.add_argument('--phys-base', type=lambda value: int(value, 0), default=PHYS_BASE)
    parser.add_argument('--boot-args-pa', type=lambda value: int(value, 0), default=BOOT_ARGS_PA)
    parser.add_argument('--device-tree', type=Path)
    parser.add_argument('--command-line', default='-v serial=3 debug=0x14e')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = prepare(args.kernel, output, args.phys_base, args.boot_args_pa, args.device_tree,
                     args.command_line)
    compiler = shutil.which('clang')
    linker = shutil.which('ld.lld')
    objcopy = shutil.which('llvm-objcopy')
    if not all((compiler, linker, objcopy)):
        parser.error('Put LLVM and lld bin directories on PATH')
    subprocess.run([compiler, '--target=aarch64-none-elf', '-c',
                    f'-DBOOT_ARGS_PA={args.boot_args_pa}',
                    f'-DKERNEL_ENTRY_PA={int(report["entry_pa"], 16)}',
                    str(ROOT / 'scripts/qemu-entry/entry.S'), '-o', str(output / 'entry.o')], check=True)
    subprocess.run([linker, '-T', str(ROOT / 'scripts/qemu-entry/link.ld'),
                    str(output / 'entry.o'), '-o', str(output / 'entry.elf')], check=True)
    subprocess.run([objcopy, '-O', 'binary', str(output / 'entry.elf'), str(output / 'entry.bin')], check=True)
    log = output / f'{args.cpu}.log'
    trace = output / f'{args.cpu}.exceptions.log'
    for previous in (log, trace):
        if previous.exists():
            previous.unlink()
    command = ['qemu-system-aarch64', '-M', 'virt,virtualization=off,secure=off',
               '-accel', 'tcg', '-cpu', args.cpu, '-m', '512', '-smp', '1',
               '-display', 'none', '-monitor', 'none', '-nic', 'none', '-no-reboot',
               '-serial', f'file:{log}', '-kernel', str(output / 'entry.bin'),
               '-d', 'int', '-D', str(trace),
               '-device', f'loader,file={output / "kernel-flat.bin"},addr={args.phys_base:#x},force-raw=on',
               '-device', f'loader,file={output / "boot-args.bin"},addr={args.boot_args_pa:#x},force-raw=on']
    started = time.monotonic()
    with (output / f'{args.cpu}.stderr.log').open('w') as errors:
        process = subprocess.Popen(command, stdout=errors, stderr=errors)
        try:
            while process.poll() is None and time.monotonic() - started < args.timeout:
                if log.exists() and 'exception captured' in log.read_text(errors='replace'):
                    break
                if trace.exists() and ('Taking exception' in trace.read_text(errors='replace')
                                       or trace.stat().st_size > 1024 * 1024):
                    break
                time.sleep(0.05)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    text = log.read_text(errors='replace') if log.exists() else ''
    exceptions = trace.read_text(errors='replace') if trace.exists() else ''
    report.update(cpu=args.cpu, seconds=round(time.monotonic() - started, 3),
                  outcome='exception' if ('exception captured' in text or 'Taking exception' in exceptions)
                  else 'no-exception-captured',
                  os_boot_demonstrated=False)
    report['qemu_exception_trace'] = exceptions[:4096]
    fault = re.search(r'with ELR 0x([0-9a-f]+)', exceptions)
    if fault:
        pc = int(fault[1], 16)
        in_virtual_segment = any(int(s['va'], 16) <= pc < int(s['va'], 16) + s['size']
                                 for s in report['segments'])
        in_physical_image = args.phys_base <= pc < args.phys_base + report['mapped_bytes']
        virtual = pc if in_virtual_segment else (
            pc - args.phys_base + int(report['virtual_base'], 16) if in_physical_image else None)
        report['fault_pc'] = hex(pc)
        report['fault_address_space'] = ('kernel-virtual' if in_virtual_segment else
                                         'physical' if in_physical_image else 'unmapped')
        if virtual is not None:
            report['fault_va'] = hex(virtual)
        binary = args.kernel.read_bytes()
        offset = 32
        for _ in range(struct.unpack_from('<I', binary, 16)[0]):
            command, size = struct.unpack_from('<II', binary, offset)
            if command == 0x19:
                name, address, length, fileoff, filesize = struct.unpack_from('<16sQQQQ', binary, offset + 8)
                if virtual is not None and address <= virtual and virtual + 4 <= address + filesize:
                    opcode = struct.unpack_from('<I', binary, fileoff + virtual - address)[0]
                    report['fault_opcode'] = hex(opcode)
                    report['fault_segment'] = name.rstrip(b'\0').decode()
                    if opcode & 0xfff00000 == 0xd5100000:
                        report['fault_msr'] = (
                            f'S{(opcode >> 19) & 3}_{(opcode >> 16) & 7}'
                            f'_C{(opcode >> 12) & 15}_C{(opcode >> 8) & 15}_{(opcode >> 5) & 7}')
            offset += size
    for register in ('CurrentEL', 'MMFR0', 'CNTFRQ', 'ESR_EL1', 'ELR_EL1', 'FAR_EL1'):
        match = re.search(register + r'=0x([0-9a-f]+)', text)
        if match:
            report[register] = '0x' + match[1]
    (output / f'{args.cpu}.json').write_text(json.dumps(report, indent=2) + '\n')
    print(text, end='')
    print(json.dumps({k: v for k, v in report.items() if k != 'segments'}, indent=2))
    if 'entering unchanged kernel' not in text:
        raise SystemExit('Probe did not reach the entry boundary; inspect stderr log')
