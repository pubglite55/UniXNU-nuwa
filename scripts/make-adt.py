#!/usr/bin/env python3
"""Generate an ADT sidecar from compiled hardware and OS/device profiles."""
import argparse
from pathlib import Path
import tomllib

from unixnu.devicetree import generate
from unixnu.profiles import merge
from unixnu.util import Error



parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--dtb', required=True, type=Path)
parser.add_argument('--os-profile', required=True, type=Path)
parser.add_argument('--board', required=True, type=Path)
parser.add_argument('--output', required=True, type=Path)
parser.add_argument('--unique-chip-id')
parser.add_argument('--data-ramdisk', action='store_true')
parser.add_argument('--trust-cache', action='store_true')
parser.add_argument('--gpu-addon', action='store_true')
args = parser.parse_args()
config = merge(tomllib.loads(args.os_profile.read_text()), tomllib.loads(args.board.read_text()))
try:
    result = generate(args.dtb, config, unique_chip_id=args.unique_chip_id,
                      data=args.data_ramdisk, trust=args.trust_cache, addon=args.gpu_addon)
except Error as error:
    parser.error(str(error))
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_bytes(result)
print(f'ADT: {args.output} ({len(result)} bytes)')
