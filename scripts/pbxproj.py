"""Read an Xcode project.pbxproj (an OpenStep property list) without plutil.

macOS `plutil -convert json` reads OpenStep plists; the plistlib-based plutil a Linux host has does not. Values come
back as plutil's JSON has them: dictionaries, lists and strings.
"""
from pathlib import Path
import re

BARE = re.compile(rb'[A-Za-z0-9_$+/:.\-]+')
ESCAPES = {b'n': b'\n', b't': b'\t', b'r': b'\r', b'"': b'"', b'\\': b'\\'}


def load(path):
    data = Path(path).read_bytes()
    at = 0

    def skip():
        nonlocal at
        while at < len(data):
            if data[at:at + 1].isspace():
                at += 1
            elif data.startswith(b'//', at):
                end = data.find(b'\n', at)
                at = len(data) if end < 0 else end + 1
            elif data.startswith(b'/*', at):
                end = data.find(b'*/', at + 2)
                if end < 0:
                    raise ValueError(f'{path}: unterminated comment')
                at = end + 2
            else:
                return

    def expect(char):
        nonlocal at
        skip()
        if data[at:at + 1] != char:
            raise ValueError(f'{path}: expected {char.decode()} at offset {at}')
        at += 1

    def value():
        nonlocal at
        skip()
        head = data[at:at + 1]
        if head == b'{':
            at += 1
            result = {}
            while True:
                skip()
                if data[at:at + 1] == b'}':
                    at += 1
                    return result
                key = value()
                expect(b'=')
                result[key] = value()
                expect(b';')
        if head == b'(':
            at += 1
            result = []
            while True:
                skip()
                if data[at:at + 1] == b')':
                    at += 1
                    return result
                result.append(value())
                skip()
                if data[at:at + 1] == b',':
                    at += 1
        if head == b'"':
            at += 1
            out = bytearray()
            while True:
                char = data[at:at + 1]
                if not char:
                    raise ValueError(f'{path}: unterminated string')
                at += 1
                if char == b'"':
                    return out.decode()
                if char == b'\\':
                    escape = data[at:at + 1]
                    at += 1
                    out += ESCAPES.get(escape, b'\\' + escape)
                else:
                    out += char
        match = BARE.match(data, at)
        if not match:
            raise ValueError(f'{path}: unexpected {head!r} at offset {at}')
        at = match.end()
        return match.group().decode()

    return value()
