#!/usr/bin/env python3
"""Bounded real original IOGPU userclient lifecycle; no device/client publication."""
import argparse,hashlib,json,shutil,socket,subprocess,tempfile,threading
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--missing-base',action='store_true');p.add_argument('--default-off',action='store_true');a=p.parse_args()
if a.missing_base and a.default_off:p.error('Select one independent control')
if subprocess.run(['pgrep','-f','qemu-system-aarch64'],capture_output=True).returncode==0:raise SystemExit('Another QEMU is running')
base=ROOT/'build/xnu-prelink/native-owner-original-client-abi-candidate';fixture=ROOT/'build'/('darwinboot-owner-hvf-original-client-abi'+('-missing-base' if a.missing_base else '-default-off' if a.default_off else ''))
if (fixture/'gdb-stop.json').exists():raise SystemExit('Preserve the existing observation before another run')
build=json.loads((ROOT/'build/native-offline-accelerator/build-report.json').read_text())
for rel,digest in build['source_sha256'].items():
 if hashlib.sha256((ROOT/rel).read_bytes()).hexdigest()!=digest:raise SystemExit('Exact compiled source required: '+rel)
cmd=['python3','scripts/probe-darwinboot-xnu.py','--kernel',str(base.with_suffix('.macho')),'--prelink-report',str(base.with_suffix('.json')),'--output',str(fixture),
 '--virtio-udif-image','.cache/firmware/target-volumes/044-76040-038.dmg','--virtio-extra-block-image','.cache/firmware/target-volumes/044-76034-038.dmg',
 '--virtio-mmio-fdt','build/virtio-block-fixture/qemu-virt.dtb','--root-match-volume-uuid','04769D26-2CA0-4825-B443-E2E5F88300F2',
 '--trust-cache','build/offline-renderbox-present-2/offline-trust.bundle','--armvirt','--armcpu','--qemu-vmm-present','--qemu-accel','hvf','--owned-memory-size','0x20000000',
 '--nvram-proxy','--crypto-hash-method','sha2-384','--amfi-platform-only','--load-apfs','--inspect-owner-root','--inspect-dyld-flags','--check-commpage',
 '--skip-initializer-traces','--skip-policy-pointer-reads','--timeout','60','--data-ramdisk','build/offline-renderbox-present-2/compiler-data-32.cdr','--qemu-ramfb','--inspect-boot-video',
 '--offline-gpu-broker','--native-air-init','--original-client-abi-probe','--break-symbol','_native_original_client_checkpoint']
if not a.missing_base:cmd+=['--load-iogpu']
if a.default_off:
 cmd.remove('--original-client-abi-probe');cmd.remove('--offline-gpu-broker');cmd.remove('--native-air-init');cmd[cmd.index('--break-symbol')+1]='_panic';cmd+=['--follow-target-main']
with tempfile.TemporaryDirectory(prefix='accel-abi-',dir='/tmp') as directory:
 path=Path(directory)/'console.sock';listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(path));listener.listen(1);listener.settimeout(1)
 stop=threading.Event();capture=bytearray();failures=[]
 def sink():
  connection=None
  try:
   while not stop.is_set():
    try:connection,_=listener.accept();break
    except socket.timeout:continue
   if connection:
    connection.settimeout(1)
    while not stop.is_set():
     try:chunk=connection.recv(4096)
     except socket.timeout:continue
     if not chunk:break
     capture.extend(chunk)
     if len(capture)>65536:failures.append('Bounded read-only console prefix exceeded');break
  except OSError as error:
   if not stop.is_set():failures.append(str(error))
  finally:
   if connection:connection.close()
 thread=threading.Thread(target=sink,daemon=True);thread.start()
 try:subprocess.run([*cmd,'--virtio-console-socket',str(path)],cwd=ROOT,check=True,timeout=180)
 finally:stop.set();listener.close();thread.join(timeout=3)
 fixture.joinpath('console-sink.json').write_text(json.dumps(dict(bytes_observed=len(capture),sha256=hashlib.sha256(capture).hexdigest(),errors=failures,
  protocol_responses_sent=0,gpu_execution=False,system_device_published=False),indent=2)+'\n')
 if failures:raise SystemExit('; '.join(failures))
print('Actual original userclient lifecycle/control observed; no device/client attached or published and no GPU protocol replies supplied')
