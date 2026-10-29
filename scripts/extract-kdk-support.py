#!/usr/bin/env python3
"""Stream a verified KDK PBZX payload, extracting only selected reference files."""
import argparse
import contextlib
import sys
import lzma
from pathlib import Path
import struct
import subprocess
import time

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('payload', type=Path, help='PBZX file, or - for a streamed package payload')
    parser.add_argument('--include', action='append', help='bsdtar include pattern; default: kernel support archives')
    parser.add_argument('--output', type=Path, default=Path('.cache/kdk-root'))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    patterns = args.include or ['*KernelSupport/*.a']
    command = ['bsdtar', '-x', '-f', '-', '--no-same-owner', '-C', str(args.output)]
    for pattern in patterns:
        command.extend(['--include', pattern])
    process = subprocess.Popen(command, stdin=subprocess.PIPE)
    count = 0
    total = 0
    try:
        with (contextlib.nullcontext(sys.stdin.buffer) if str(args.payload) == '-'
              else args.payload.open('rb')) as source:
            if source.read(4) != b'pbzx':
                raise ValueError('Expected PBZX payload')
            maximum = struct.unpack('>Q', source.read(8))[0]
            if maximum != 16 * 1024**2:
                raise ValueError('Unexpected PBZX chunk size')
            while header := source.read(16):
                if len(header) != 16:
                    raise ValueError('Truncated chunk header')
                expected, compressed = struct.unpack('>QQ', header)
                if expected > maximum or compressed > 2 * maximum:
                    raise ValueError('Invalid PBZX chunk extent')
                block = source.read(compressed)
                if len(block) != compressed:
                    raise ValueError('Truncated PBZX block')
                if block.startswith(b'\xfd7zXZ\0'):
                    block = lzma.decompress(block, memlimit=256 * 1024**2)
                if len(block) != expected:
                    raise ValueError('Decompressed PBZX chunk has wrong length')
                process.stdin.write(block)
                total += len(block)
                count += 1
        process.stdin.close()
        if process.wait() != 0:
            raise RuntimeError('KDK support archive extraction failed')
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
    files = [path for path in args.output.rglob('*') if path.is_file()]
    if not files:
        raise SystemExit('No selected KDK files were extracted')
    print(f'Selected output contains {len(files)} files from {count} chunks ({total} streamed bytes) '
          f'in {time.monotonic() - started:.1f}s')
