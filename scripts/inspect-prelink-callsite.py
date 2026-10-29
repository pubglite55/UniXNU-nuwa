#!/usr/bin/env python3
"""Decode an observed prelinked callsite and resolve real kernel/GOT targets."""
import argparse
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import backed_offset, exports, macho

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('candidate', type=Path)
parser.add_argument('--at', required=True, type=lambda value: int(value, 0))
parser.add_argument('--bytes', type=lambda value: int(value, 0), default=256)
args = parser.parse_args()
if args.at % 4 or args.bytes % 4 or not 0 < args.bytes <= 4096:
    parser.error('Use aligned AArch64 instructions and at most 4096 bytes')
tool = shutil.which('llvm-mc')
if not tool:
    raise SystemExit('llvm-mc is required on PATH')
data = args.candidate.read_bytes()
image = macho(data)
symbols = exports(data, image)


def read(va, size):
    at = backed_offset(image['segments'], va, size, len(data))
    return data[at:at + size]


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def adrp(word, pc):
    return (pc & ~4095) + (signed(((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3), 21) << 12)


def literal(va):
    for segment in image['segments']:
        if segment['va'] <= va < segment['va'] + segment['filesize']:
            raw = read(va, min(180, segment['va'] + segment['filesize'] - va)).split(b'\0', 1)[0]
            if raw and all(byte in (9, 10, 13) or 32 <= byte < 127 for byte in raw):
                return repr(raw.decode())
    return ''


def branch_target(va):
    if va in symbols:
        return ','.join(symbols[va])
    try:
        first, second, third = struct.unpack('<3I', read(va, 12))
        if (first & 0x9f000000 == 0x90000000 and second & 0xffc00000 == 0xf9400000
                and third & 0xfffffc1f == 0xd61f0000 and first & 31 == (second >> 5) & 31
                and second & 31 == (third >> 5) & 31):
            slot = adrp(first, va) + ((second >> 10) & 0xfff) * 8
            target, = struct.unpack('<Q', read(slot, 8))
            return f'GOT {slot:#x} -> {target:#x} ' + ','.join(symbols.get(target, []))
    except ValueError:
        pass
    return ''


blob = read(args.at, args.bytes)
text = '\n'.join(' '.join(f'0x{x:02x}' for x in blob[i:i + 4]) for i in range(0, len(blob), 4))
result = subprocess.run([tool, '--disassemble', '--triple=aarch64-apple-darwin'],
                         input=text, capture_output=True, text=True, check=True)
lines = [line.strip() for line in result.stdout.splitlines() if line.strip() and line.strip() != '.text']
if len(lines) != len(blob) // 4:
    raise SystemExit('Decoder omitted an instruction; refuse to mislabel addresses')
previous = None
for index, line in enumerate(lines):
    va = args.at + index * 4
    word, = struct.unpack_from('<I', blob, index * 4)
    note = ''
    if word & 0x7c000000 == 0x14000000:
        target = va + (signed(word & 0x3ffffff, 26) << 2)
        note = f' -> {target:#x} ' + branch_target(target)
    if word & 0x7f000000 == 0x11000000 and previous is not None:
        prev_word, prev_pc = previous
        if prev_word & 0x9f000000 == 0x90000000 and prev_word & 31 == (word >> 5) & 31:
            target = adrp(prev_word, prev_pc) + (((word >> 10) & 0xfff) << (12 if word & (1 << 22) else 0))
            note = f' -> {target:#x} ' + literal(target)
    print(f'{va:#018x}  {line}{note}')
    previous = (word, va)
