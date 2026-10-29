#!/usr/bin/env python3
"""Build the matching Darwin 23 pthread kernel component and its real registration."""
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from xnu_symbols import kernel_names
SOURCE = ROOT / 'refer/libpthread'
REVISION = 'c0e60fb5ecfc54cf379c261d3f9572cc22ded891'
if subprocess.check_output(['git', '-C', SOURCE, 'rev-parse', 'HEAD'], text=True).strip() != REVISION:
    raise SystemExit('Unexpected libpthread source revision')
if subprocess.check_output(['git', '-C', SOURCE, 'status', '--porcelain'], text=True):
    raise SystemExit('The libpthread reference must remain immutable')
WORK = ROOT / '.cache/libpthread-work'
if not WORK.exists():
    subprocess.run(['git', 'clone', '--shared', SOURCE, WORK], check=True)
for patch in sorted((ROOT / 'patches/libpthread').glob('*.patch')):
    if subprocess.run(['git', '-C', WORK, 'apply', '--reverse', '--check', patch],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        subprocess.run(['git', '-C', WORK, 'apply', patch], check=True)
SOURCE = WORK
OUT = ROOT / 'build/libpthread-kernel'
OUT.mkdir(parents=True, exist_ok=True)
recipe = ROOT / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/prng_random.o.json'
record = json.loads(recipe.read_text().strip().rstrip(','))
sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()


def compile_one(source, destination, namespace=None):
    if source.name == 'source_pthread_bootstrap.c':
        command = []
        arguments = record['arguments']
        index = 0
        while index < len(arguments):
            value = arguments[index]
            if value == record['file']:
                command.append(str(source))
            elif value == '-o':
                command.extend(['-o', str(destination)])
                index += 1
            else:
                command.append(value)
            index += 1
    else:
        framework = ROOT / '.cache/fakeroot/System/Library/Frameworks/Kernel.framework/Versions/A'
        command = ['xcrun', '--sdk', 'iphoneos', 'clang', '-target', 'arm64-apple-ios17.0',
                   '-isysroot', sdk, '-mkernel', '-ffreestanding', '-fno-builtin', '-fno-stack-check',
                   '-std=gnu11', '-fblocks', '-O2', '-mno-implicit-float',
                   '-DKERNEL=1', '-DKERNEL_PRIVATE=1', '-DXNU_KERNEL_PRIVATE=1',
                   '-DMACH_KERNEL_PRIVATE=1', '-DMACH_ASSERT=1', '-DDEBUG=1',
                   '-D__PTHREAD_EXPOSE_INTERNALS__=1', '-DABSOLUTETIME_SCALAR_TYPE=1', '-DNEEDS_SCHED_CALL_T=1',
                   '-I', str(SOURCE / 'private'), '-I', str(SOURCE / 'include'), '-I', str(SOURCE),
                   '-I', str(framework / 'PrivateHeaders'), '-I', str(framework / 'Headers'),
                   '-Wno-deprecated-declarations', '-c', str(source), '-o', str(destination)]
    if namespace:
        command += ['-include', str(namespace)]
    result = subprocess.run(command, cwd=record['directory'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    destination.with_suffix('.log').write_text(result.stdout)
    if result.returncode:
        raise SystemExit(result.stdout[-4500:])
    data = destination.read_bytes()
    if struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
        raise SystemExit('Unexpected pthread object architecture')
    offset = 32
    deployment = None
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, length = struct.unpack_from('<II', data, offset)
        if cmd == 0x32:
            deployment = struct.unpack_from('<II', data, offset + 8)
        offset += length
    if deployment != (2, 0x110000):
        raise SystemExit(f'Unexpected pthread deployment: {deployment}')


def names(path, mode, global_only=True):
    result = subprocess.check_output(['xcrun', 'nm', *(['-g'] if global_only else []), mode, '-j', path], text=True)
    return {line.strip() for line in result.splitlines() if line.startswith('_')}


sources = [SOURCE / 'kern' / name for name in ('kern_init.c', 'kern_support.c', 'kern_synch.c')]
objects = []
for source in sources:
    destination = OUT / (source.stem + '.o')
    compile_one(source, destination)
    objects.append(destination)
kernel_names = kernel_names(ROOT, global_only=False)
definitions = set().union(*(names(path, '-U') for path in objects))
collisions = definitions & kernel_names
if collisions:
    namespace = OUT / 'namespace.h'
    namespace.write_text(''.join(f'#define {name[1:]} pthread519_{name[1:]}\n' for name in sorted(collisions)))
    for source, destination in zip(sources, objects):
        compile_one(source, destination, namespace)
definitions = set().union(*(names(path, '-U') for path in objects))
imports = set().union(*(names(path, '-u') for path in objects)) - definitions
# The component is statically linked: os_log's DSO identity is the real
# executable Mach-O header, synthesized by the Mach-O executable linker.
missing = sorted(imports - kernel_names - {'___dso_handle'})
report = {'revision': REVISION, 'sources': 3, 'ordinary_arm64_ios17_audited': True,
          'namespace_collisions_isolated': sorted(collisions), 'missing_kernel_names': missing,
          'linker_synthesized_symbols': ['___dso_handle'],
          'registration_observed': False}
(OUT / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
if not {'_pthread_kern', '_current_uthread'} <= collisions:
    raise SystemExit('Missing expected pthread/XNU static symbol isolation')
if missing:
    raise SystemExit(f'Unavailable real kernel imports: {missing}')
archive = OUT / 'libpthread_kernel.a'
archive.unlink(missing_ok=True)
compile_one(ROOT / '.cache/xnu-work/bsd/kern/source_pthread_bootstrap.c', OUT / 'source_pthread_bootstrap.o')
subprocess.run(['xcrun', 'ar', 'rcs', archive, *objects, OUT / 'source_pthread_bootstrap.o'], check=True)
print('Matching libpthread: 3 real C sources + bootstrap, ARM64/iOS 17 audit, no unavailable kernel names')
