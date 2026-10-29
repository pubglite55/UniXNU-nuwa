#!/usr/bin/env python3
"""Decode the exact integer tokens photographed from the native UI stack probe."""
import argparse
import json
import re
import sys
from pathlib import Path

DIGITS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_'
TOKEN = r'[A-Za-z0-9_-]+'
PATTERN = re.compile(
    r'(?P<role>[BCLSTU])(?P<index>\d+)x(?P<count>\d+)\s+'
    r'(?:(?P<extension>f5)\s+' + r'\s+'.join('(?P<f%d>%s)' % (i, TOKEN) for i in range(5, 9)) +
    r'(?: p(?P<peer>-?\d+)/e(?P<peer_error>\d+))?|' +
    r'\s+'.join('(?P<a%d>%s)' % (i, TOKEN) for i in range(6)) + r'\s+!(?P<error>\d+))')
DETAIL = re.compile(r'(?P<role>[BCLSTU]) FP(?P<first>01|09|17|25)\s+' + r'\s+'.join('(?P<f%d>%s)' % (i, TOKEN) for i in range(8)))


def address(token):
    result = 0
    for digit in token:
        result = result * 64 + DIGITS.index(digit)
    if result >= 1 << 39:
        raise ValueError('token exceeds native user address range: ' + token)
    return hex(result)


def decode(text):
    entries = {}
    for m in PATTERN.finditer(text):
        role, index, count = m['role'], int(m['index']), int(m['count'])
        key = (role, index)
        entry = entries.setdefault(key, dict(role=role, index=index, count=count))
        if entry['count'] != count:
            raise ValueError('mixing different captures for one thread group')
        if m['extension']:
            entry['frames_5_8'] = [address(m['f%d' % i]) for i in range(5, 9)]
            if m['peer'] is not None:
                entry.update(peer=int(m['peer']), peer_error=int(m['peer_error']))
        else:
            entry.update(pc=address(m['a0']), lr=address(m['a1']),
                         frames_1_4=[address(m['a%d' % i]) for i in range(2, 6)], error=int(m['error']))
    for m in DETAIL.finditer(text):
        key = (m['role'], 1)
        entry = entries.setdefault(key, dict(role=m['role'], index=1))
        first = int(m['first'])
        entry['frames_%d_%d' % (first, first + 7)] = [address(m['f%d' % i]) for i in range(8)]
    return list(entries.values())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', nargs='?', type=Path, help='transcribed screen text; otherwise stdin')
    args = parser.parse_args()
    results = decode(args.input.read_text() if args.input else sys.stdin.read())
    if not results:
        parser.error('no complete UI trace rows found')
    print(json.dumps(results, indent=2))
