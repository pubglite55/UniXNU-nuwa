#!/usr/bin/env python3
"""Check generated metadata with the pinned XNU XML tag/string lexer on host.

This checks lexer compatibility, not the complete kernel object parser or boot.
The actual source functions are compiled unchanged into ignored build output.
"""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
from native_prelink import macho

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('candidate', type=Path)
args = parser.parse_args()
data = args.candidate.read_bytes()
info = next(s for s in macho(data)['segments'] if s['name'] == '__PRELINK_INFO')
xml = data[info['fileoff']:info['fileoff'] + info['filesize']].split(b'\0')[0] + b'\0'
source = (ROOT / 'refer/xnu/libkern/libkern/c++/OSUnserializeXMLSharedImplementation.h').read_text()
start = source.index('#define TAG_MAX_LENGTH')
end = source.index('static long long\ngetNumber', start)
lexer = source[start:end]
output = ROOT / 'build/xnu-prelink/xml-lexer'
output.mkdir(parents=True, exist_ok=True)
(output / 'metadata.xml').write_bytes(xml)
program = r'''#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { const char *parseBuffer; int parseBufferIndex; int lineNumber; } parser_state_t;
#define safe_free(pointer, size) free(pointer)
''' + lexer + r'''
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *f = fopen(argv[1], "rb"); if (!f) return 2;
    fseek(f, 0, SEEK_END); long size = ftell(f); rewind(f);
    char *data = calloc((size_t)size + 1, 1); if (!data) return 2;
    if (fread(data, 1, (size_t)size, f) != (size_t)size) return 2;
    fclose(f);
    parser_state_t parser = {data, 0, 1}; parser_state_t *state = &parser; unsigned count = 0;
    while (currentChar()) {
        if (currentChar() != '<') { (void)nextChar(); continue; }
        int before = state->parseBufferIndex;
        char tag[TAG_MAX_LENGTH], attributes[TAG_MAX_ATTRIBUTES][TAG_MAX_LENGTH], values[TAG_MAX_ATTRIBUTES][TAG_MAX_LENGTH];
        int attr_count;
        int type = getTag(state, tag, &attr_count, attributes, values);
        if (!type || ((!strcmp(tag, "true") || !strcmp(tag, "false")) && type != TAG_EMPTY)) {
            fprintf(stderr, "Actual XNU tag lexer rejects byte %d\n", before); return 1;
        }
        if (type == TAG_START && (!strcmp(tag, "key") || !strcmp(tag, "string"))) {
            int allocated; char *decoded = getString(state, &allocated);
            if (!decoded) { fprintf(stderr, "Actual XNU string lexer rejects byte %d\n", before); return 1; }
            free(decoded);
        }
        count++;
    }
    printf("PASS: actual pinned XNU tag/string lexer accepts %u tags; full object parser not claimed\n", count);
    free(data); return 0;
}
'''
(output / 'lexer.c').write_text(program)
subprocess.run(['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                str(output / 'lexer.c'), '-o', str(output / 'check')], check=True)
subprocess.run([str(output / 'check'), str(output / 'metadata.xml')], check=True)
