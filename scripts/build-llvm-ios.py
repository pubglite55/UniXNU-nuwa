#!/usr/bin/env python3
"""Cross-build the pinned LLVM AIR-reader dependencies for ordinary ARM64/iOS17."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'.cache/llvm-ios-source'
OUT=ROOT/'build/llvm-ios'
REV='0d261d1ca552c95a8f007e061c787ac7132fbcbc'
VERSION='23.1.3'
OUT.mkdir(parents=True,exist_ok=True)

def read(cmd):return subprocess.check_output([str(v) for v in cmd],text=True,timeout=30).strip()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(cmd,log,timeout):
    with (OUT/log).open('w') as f:
        process=subprocess.Popen([str(v) for v in cmd],stdout=f,stderr=subprocess.STDOUT)
        start=time.monotonic()
        while process.poll() is None:
            if time.monotonic()-start>timeout:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()
                raise SystemExit('Native dependency build stopped at disk/time bound; see '+log)
            time.sleep(1)
        if process.returncode:raise SystemExit('Native dependency build failed; see '+log)

if not (SOURCE/'.git').exists():
    run(['git','clone','--filter=blob:none','--depth','1','--single-branch','--branch','llvmorg-23.1.3',
         '--sparse','https://github.com/llvm/llvm-project.git',SOURCE],'fetch.log',120)
if read(['git','-C',SOURCE,'rev-parse','HEAD'])!=REV:raise SystemExit('Pinned LLVM release differs')
if read(['git','-C',SOURCE,'status','--porcelain']):raise SystemExit('LLVM source must match recorded patches')
# LLVM23 uses only libc's common-utility headers; this does not build or
# replace the target system libc. Omit LLVM tests/docs/examples entirely.
patterns='/llvm/*\n!/llvm/test/\n!/llvm/unittests/\n!/llvm/benchmarks/\n!/llvm/examples/\n!/llvm/docs/\n/cmake/\n/third-party/\n/libc/\n'
current=(SOURCE/'.git/info/sparse-checkout').read_text() if (SOURCE/'.git/info/sparse-checkout').exists() else ''
if current!=patterns:
    subprocess.run(['git','-C',SOURCE,'sparse-checkout','set','--no-cone','--stdin'],input=patterns,text=True,check=True,timeout=120)
config=shutil.which('llvm-config')
if not config and shutil.which('brew'):config=str(Path(read(['brew','--prefix','llvm']))/'bin/llvm-config')
if not config or read([config,'--version'])!=VERSION:raise SystemExit('Matching native host TableGen/config required')
tblgen=Path(read([config,'--bindir']))/'llvm-tblgen'
if not tblgen.is_file():raise SystemExit('Missing qualified host TableGen')
sdk=read(['xcrun','--sdk','iphoneos','--show-sdk-path'])
clang=read(['xcrun','--sdk','iphoneos','--find','clang']);clangxx=read(['xcrun','--sdk','iphoneos','--find','clang++'])
args=['cmake','-G','Ninja','-S',SOURCE/'llvm','-B',OUT,
    '-DCMAKE_SYSTEM_NAME=iOS','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_OSX_ARCHITECTURES=arm64',
    '-DCMAKE_OSX_DEPLOYMENT_TARGET=17.0','-DCMAKE_OSX_SYSROOT='+sdk,
    '-DCMAKE_C_COMPILER='+clang,'-DCMAKE_CXX_COMPILER='+clangxx,
    '-DCMAKE_C_COMPILER_TARGET=arm64-apple-ios17.0','-DCMAKE_CXX_COMPILER_TARGET=arm64-apple-ios17.0',
    '-DCMAKE_C_FLAGS=-fstack-protector-strong','-DCMAKE_CXX_FLAGS=-fstack-protector-strong',
    '-DLLVM_DEFAULT_TARGET_TRIPLE=arm64-apple-ios17.0','-DLLVM_TARGETS_TO_BUILD=',
    '-DLLVM_TABLEGEN='+str(tblgen),'-DLLVM_ENABLE_ASSERTIONS=ON',
    '-DBUILD_SHARED_LIBS=OFF','-DLLVM_BUILD_LLVM_DYLIB=OFF','-DLLVM_LINK_LLVM_DYLIB=OFF',
    '-DLLVM_ENABLE_PROJECTS=','-DLLVM_ENABLE_RUNTIMES=']
for name in ['LLVM_INCLUDE_TESTS','LLVM_BUILD_TESTS','LLVM_INCLUDE_TOOLS','LLVM_BUILD_TOOLS',
             'LLVM_BUILD_UTILS','LLVM_INCLUDE_UTILS','LLVM_INCLUDE_EXAMPLES','LLVM_INCLUDE_BENCHMARKS','LLVM_INCLUDE_DOCS',
             'LLVM_ENABLE_ZLIB','LLVM_ENABLE_ZSTD','LLVM_ENABLE_LIBXML2','LLVM_ENABLE_TERMINFO','LLVM_ENABLE_LIBEDIT','LLVM_ENABLE_LIBPFM']:
    args+=['-D'+name+'=OFF']
run(args,'configure.log',120)
run(['cmake','--build',OUT,'--parallel','4','--target','LLVMBitReader','LLVMBitWriter','LLVMTargetParser'],'build.log',600)
archives=sorted((OUT/'lib').glob('libLLVM*.a'))
if not archives:raise SystemExit('No target archives produced')
report=dict(llvm_revision=REV,llvm_tree=read(['git','-C',SOURCE,'rev-parse','HEAD^{tree}']),llvm_version=VERSION,
    host_tblgen_sha256=sha(tblgen),sdk_version=read(['xcrun','--sdk','iphoneos','--show-sdk-version']),
    target='arm64-apple-ios17.0',native_compiler_runtime_executed=False,
    archives={p.name:dict(bytes=p.stat().st_size,sha256=sha(p)) for p in archives})
(OUT/'build-report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: LLVM23 AIR-reader/IR dependencies built for ordinary ARM64/iOS17; target runtime not executed')
