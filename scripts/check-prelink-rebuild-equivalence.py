#!/usr/bin/env python3
"""Compare rebuild bytes, excluding only UUID, N_OSO timestamps and derived KCID.

This does not qualify a replacement boot image. Keep the exact image that was
executed; the check only explains nondeterminism in a source rebuild.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def normalized(data):
    b = bytearray(data)
    if struct.unpack_from('<III', b) != (0xfeedfacf, 0x100000c, 0):
        raise ValueError('Expected ordinary ARM64 Mach-O')
    at = 32
    counts = {'uuid': 0, 'oso_timestamps': 0, 'derived_kcid': 0}
    for _ in range(struct.unpack_from('<I', b, 16)[0]):
        command, size = struct.unpack_from('<II', b, at)
        if size < 8 or at + size > len(b):
            raise ValueError('Malformed load command')
        if command == 0x1b:
            if size != 24: raise ValueError('Malformed UUID')
            b[at+8:at+24] = bytes(16); counts['uuid'] += 1
        elif command == 2:
            offset, count, _, _ = struct.unpack_from('<4I', b, at+8)
            if offset + count*16 > len(b): raise ValueError('Malformed symbols')
            for n in range(count):
                item = offset+n*16
                if b[item+4] == 0x66:  # N_OSO: object-path debug entry, value is timestamp
                    b[item+8:item+16] = bytes(8); counts['oso_timestamps'] += 1
        elif command == 0x19 and bytes(b[at+8:at+24]).rstrip(b'\0') == b'__PRELINK_INFO':
            offset, length = struct.unpack_from('<QQ', b, at+40)
            if offset+length > len(b): raise ValueError('Malformed prelink info')
            for m in re.finditer(rb'<key>_PrelinkKCID</key><data>([A-Za-z0-9+/]{22}==)</data>',b[offset:offset+length]):
                lo, hi = m.span(1); b[offset+lo:offset+hi] = b'0'*(hi-lo); counts['derived_kcid'] += 1
        at += size
    if counts['uuid'] != 1 or counts['derived_kcid'] != 1 or not counts['oso_timestamps']:
        raise ValueError('Unexpected identity/debug metadata')
    return bytes(b), counts


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--qualified',required=True,type=Path)
    p.add_argument('--rebuilt',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args();a.output.unlink(missing_ok=True)
    old=a.qualified.read_bytes();new=a.rebuilt.read_bytes()
    x,xc=normalized(old);y,yc=normalized(new)
    if x != y or xc != yc: raise ValueError('Rebuild differs beyond UUID/debug timestamps/derived KCID')
    result={'passed':True,'qualified_sha256':hashlib.sha256(old).hexdigest(),
            'rebuilt_sha256':hashlib.sha256(new).hexdigest(),'normalized_sha256':hashlib.sha256(x).hexdigest(),
            'ignored_metadata_fields':xc,'replacement_image_qualified':False}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
    print('PASS: rebuild differs only in enumerated identity/debug metadata; retain executed image')


if __name__=='__main__': main()
