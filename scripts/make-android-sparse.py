#!/usr/bin/env python3
"""Convert a raw image to an Android sparse image (libsparse format) without extra tools.

`fastboot flash <partition> <big raw file>` fails on this host (fastboot 37 reads the file end to
copy an AVB footer and aborts with "Failed reading from <partition>" before sending anything); for
sparse input it skips that step. All-zero 4096-byte blocks become FILL chunks with value 0 (written
as zeros, never DONT_CARE), everything else RAW chunks, so the expanded content equals the input
byte for byte. The result is verified by expanding it and comparing SHA-256 with the input.
"""
import argparse
import hashlib
from pathlib import Path
import struct
import sys

BLOCK = 4096
MAGIC = 0xED26FF3A
RAW, FILL, DONT_CARE, CRC32 = 0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4
MAX_RAW_BLOCKS = 4096          # 16 MiB per RAW chunk
ZERO = bytes(BLOCK)


def convert(source, target):
    size = source.stat().st_size
    if size % BLOCK:
        raise SystemExit('Input size must be a multiple of 4096')
    total_blocks = size // BLOCK
    chunks = 0
    with open(source, 'rb') as src, open(target, 'wb') as out:
        out.write(b'\0' * 28)                      # header, rewritten at the end
        pending = bytearray()                      # blocks of the current RAW run
        pending_blocks = 0
        zero_run = 0

        def flush_raw():
            nonlocal pending, pending_blocks, chunks
            if pending_blocks:
                out.write(struct.pack('<HHII', RAW, 0, pending_blocks, 12 + len(pending)))
                out.write(pending)
                chunks += 1
                pending = bytearray()
                pending_blocks = 0

        def flush_zero():
            nonlocal zero_run, chunks
            if zero_run:
                out.write(struct.pack('<HHII', FILL, 0, zero_run, 12 + 4))
                out.write(struct.pack('<I', 0))
                chunks += 1
                zero_run = 0

        remaining = total_blocks
        while remaining:
            take = min(remaining, 1024)
            data = src.read(take * BLOCK)
            if len(data) != take * BLOCK:
                raise SystemExit('Short read')
            for offset in range(0, len(data), BLOCK):
                block = data[offset:offset + BLOCK]
                if block == ZERO:
                    flush_raw()
                    zero_run += 1
                    if zero_run == 0x10000000:
                        flush_zero()
                else:
                    flush_zero()
                    pending += block
                    pending_blocks += 1
                    if pending_blocks == MAX_RAW_BLOCKS:
                        flush_raw()
            remaining -= take
        flush_raw()
        flush_zero()
        out.seek(0)
        out.write(struct.pack('<IHHHHIIII', MAGIC, 1, 0, 28, 12, BLOCK, total_blocks, chunks, 0))
    return total_blocks, chunks


def expand_hash(path, expect_blocks):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        magic, major, minor, fhs, chs, blk, total, chunks, _ = struct.unpack('<IHHHHIIII', handle.read(28))
        if magic != MAGIC or (fhs, chs, blk) != (28, 12, BLOCK) or total != expect_blocks:
            raise SystemExit('Bad sparse header')
        seen = 0
        for _ in range(chunks):
            kind, _, count, total_sz = struct.unpack('<HHII', handle.read(12))
            if kind == RAW:
                left = count * BLOCK
                if total_sz != 12 + left:
                    raise SystemExit('Bad RAW chunk size')
                while left:
                    data = handle.read(min(left, 8 << 20))
                    digest.update(data)
                    left -= len(data)
            elif kind == FILL:
                value = handle.read(4)
                if value != b'\0\0\0\0':
                    raise SystemExit('Unexpected fill value')
                zeros = bytes(1 << 20)
                left = count * BLOCK
                while left:
                    step = min(left, len(zeros))
                    digest.update(zeros[:step])
                    left -= step
            else:
                raise SystemExit(f'Unexpected chunk type {kind:#x}')
            seen += count
        if seen != total:
            raise SystemExit('Chunk blocks do not add up')
    return digest.hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(8 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('target', type=Path)
    args = parser.parse_args()
    blocks, chunks = convert(args.source, args.target)
    print(f'{args.target.name}: {blocks} blocks, {chunks} chunks, {args.target.stat().st_size} bytes')
    original = sha256_file(args.source)
    expanded = expand_hash(args.target, blocks)
    print('input    sha256', original)
    print('expanded sha256', expanded)
    if original != expanded:
        args.target.unlink()
        raise SystemExit('Sparse expansion differs from the input; removed')
    print('OK: sparse image expands to the exact input')


if __name__ == '__main__':
    main()
