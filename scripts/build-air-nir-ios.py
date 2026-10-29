#!/usr/bin/env python3
"""Cross-build the actual AIR/NIR/IR3 compiler for ordinary ARM64/iOS17."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import time
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'build/mesa-ir3-ios';TOOLS=ROOT/'build/air-nir-ios';LLVM=ROOT/'build/llvm-ios'
SOURCE=ROOT/'.cache/mesa-work';LLVMSOURCE=ROOT/'.cache/llvm-ios-source'
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--configure-only',action='store_true');a=p.parse_args()
TOOLS.mkdir(parents=True,exist_ok=True)
def read(cmd):return subprocess.check_output([str(v) for v in cmd],text=True,timeout=30).strip()
def run(cmd,log,timeout):
    with (TOOLS/log).open('w') as f:
        process=subprocess.Popen([str(v) for v in cmd],stdout=f,stderr=subprocess.STDOUT,env=env)
        start=time.monotonic()
        while process.poll() is None:
            if time.monotonic()-start>timeout:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()
                raise SystemExit('Native compiler stopped at disk/time bound; see '+log)
            time.sleep(1)
        if process.returncode:raise SystemExit('Native compiler failed; see '+log)
pins=json.loads((ROOT/'scripts/data/adreno-compiler-inputs.json').read_text())
if read(['git','-C',SOURCE,'rev-parse','HEAD'])!=pins['mesa']['commit']:raise SystemExit('Pinned Mesa source differs')
for patch in pins['patches']:
    subprocess.run(['git','-C',SOURCE,'apply','--reverse','--check',ROOT/patch],check=True,capture_output=True)
sdk=read(['xcrun','--sdk','iphoneos','--show-sdk-path'])
clang=read(['xcrun','--sdk','iphoneos','--find','clang']);clangxx=read(['xcrun','--sdk','iphoneos','--find','clang++'])
config=shutil.which('llvm-config')
if not config and shutil.which('brew'):config=str(Path(read(['brew','--prefix','llvm']))/'bin/llvm-config')
if not config or read([config,'--version'])!='23.1.3':raise SystemExit('Need the same host LLVM config for component graph')
libs=shlex.split(read([config,'--link-static','--libs','core','bitreader','bitwriter','analysis','targetparser']))
wrapper=TOOLS/'llvm-config-ios'
cxxflags=['-I'+str(LLVMSOURCE/'llvm/include'),'-I'+str(LLVM/'include'),'-std=c++17','-stdlib=libc++','-fno-exceptions',
          '-D__STDC_CONSTANT_MACROS','-D__STDC_FORMAT_MACROS','-D__STDC_LIMIT_MACROS']
wrapper.write_text('#!/usr/bin/env python3\nimport sys\n'+
    'if sys.argv[1:]==["--version"]: print("23.1.3")\n'+
    'elif "--cxxflags" in sys.argv: print('+repr(' '.join(cxxflags))+')\n'+
    'elif "--libs" in sys.argv: print('+repr(' '.join(['-L'+str(LLVM/'lib')]+libs))+')\n'+
    'else: raise SystemExit("Unsupported native component config request")\n')
wrapper.chmod(0o755)
cross=TOOLS/'ios.cross'
flags=['-target','arm64-apple-ios17.0','-isysroot',sdk,'-fstack-protector-strong']
cross.write_text('[binaries]\nc = '+repr(clang)+'\ncpp = '+repr(clangxx)+'\nar = '+repr(read(['xcrun','--sdk','iphoneos','--find','ar']))+'\n'+
    'objc = '+repr(clang)+'\nstrip = '+repr(read(['xcrun','--sdk','iphoneos','--find','strip']))+'\npkg-config = \'/usr/bin/false\'\n'+
    '[host_machine]\nsystem = \'darwin\'\ncpu_family = \'aarch64\'\ncpu = \'arm64\'\nendian = \'little\'\n'+
    '[properties]\nneeds_exe_wrapper = true\n'+
    '[built-in options]\nc_args = '+repr(flags)+'\ncpp_args = '+repr(flags)+'\nobjc_args = '+repr(flags)+'\nobjc_link_args = '+repr(flags)+'\nc_link_args = '+repr(flags)+'\ncpp_link_args = '+repr(flags)+'\n')
env={k:v for k,v in os.environ.items() if not k.startswith(('IR3_','FD_MESA_','NIR_','MESA_SHADER_'))}
env.update(PATH=str(ROOT/'.cache/mesa-tools/bin')+':'+str(ROOT/'.cache/mesa-venv/bin')+':'+env['PATH'],
           CC=clang,CXX=clangxx,CFLAGS='',CXXFLAGS='',CPPFLAGS='',LDFLAGS='')
options=['-Dgallium-drivers=','-Dvulkan-drivers=','-Dplatforms=','-Dglx=disabled','-Degl=disabled',
    '-Dgbm=disabled','-Dopengl=false','-Dgles1=disabled','-Dgles2=disabled','-Dllvm=disabled',
    '-Dshared-glapi=disabled','-Dxmlconfig=disabled','-Dshader-cache=disabled','-Dtools=freedreno',
    '-Dbuild-tests=false','-Dvideo-codecs=','-Dlibunwind=disabled','-Dlmsensors=disabled',
    '-Dvalgrind=disabled','-Dexpat=disabled','-Dzstd=disabled','-Dzlib=disabled',
    '-Dbuildtype=debugoptimized','-Db_ndebug=false','-Doffline-air-nir-dir='+str(ROOT/'kits/AirNir'),
    '-Doffline-air-nir-llvm-config='+str(wrapper)]
meson=ROOT/'.cache/mesa-venv/bin/meson'
if not (OUT/'build.ninja').exists():run([meson,'setup',OUT,SOURCE,'--cross-file',cross,'--wrap-mode=nodownload',*options],'configure.log',180)
else:run([meson,'configure',OUT,*options],'configure.log',60)
if a.configure_only:
    print('PASS: native AIR/NIR/IR3 cross configuration; build and runtime remain unqualified')
    raise SystemExit(0)
report=json.loads((LLVM/'build-report.json').read_text())
if report['llvm_revision']!='0d261d1ca552c95a8f007e061c787ac7132fbcbc':raise SystemExit('Native LLVM identity differs')
for name,digest in report['archives'].items():
    if hashlib.sha256((LLVM/'lib'/name).read_bytes()).hexdigest()!=digest['sha256']:raise SystemExit('Native LLVM archive differs')
run(['ninja','-C',OUT,'-j4','src/freedreno/ir3/air_nir'],'build.log',600)
exe=OUT/'src/freedreno/ir3/air_nir'
(TOOLS/'build-report.json').write_text(json.dumps(dict(llvm_revision=report['llvm_revision'],mesa_revision=pins['mesa']['commit'],
    target='arm64-apple-ios17.0',sdk_version=read(['xcrun','--sdk','iphoneos','--show-sdk-version']),
    executable_bytes=exe.stat().st_size,executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
    kit_sources={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'kits/AirNir').glob('*')) if p.suffix in ('.h','.c','.cpp')},
    target_runtime_executed=False,generated_shader_executed=False,metal_device=False),indent=2)+'\n')
print('PASS: actual AIR/NIR/IR3 compiler cross-built for ARM64/iOS17; runtime/Metal not qualified')
