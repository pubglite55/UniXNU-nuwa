#!/usr/bin/env python3
"""Qualify actual host shared-event values/listeners and real exported Metal handles."""
import argparse,hashlib,json,os,re,socket,struct,subprocess,tempfile,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--api-validation',action='store_true');a=p.parse_args()
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'build/host-metal-shared-events';OUT.mkdir(exist_ok=True)
def require(v,s):
 if not v:raise SystemExit(s)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def words(*v):return struct.pack('<'+'Q'*len(v),*v)
exe=ROOT/'build/host-metal/host-metal-originals';build=json.loads((exe.parent/'qualification.json').read_text())
require(sha(exe)==build['process_sha256'],'Exact real host executable')
for rel,digest in build['backend_sources'].items():require(sha(ROOT/rel)==digest,'Exact backend source: '+rel)
base=ROOT/'.cache/firmware/target-volumes/os-mount/System/Library'
paths=[base/'Frameworks/QuartzCore.framework/default.metallib',base/'PrivateFrameworks/RenderBox.framework/default.metallib']
require([sha(p) for p in paths]==['606f913adf520420f9b4bb666efb782a68c830f082f1e559e17b20d0d13adbc9','d76883f626b1527c36fb0940cf27dcade503a55cf2fa05c8f7a247a40ccebec4'],'Exact unchanged original libraries')
requests={};observed=[]
with tempfile.TemporaryDirectory(prefix='metal-fences-',dir='/tmp') as directory:
 path=Path(directory)/'gpu.sock'
 with (OUT/'host-report.json').open('w') as output,(OUT/'host-stderr.log').open('w') as errors:
  process=subprocess.Popen([str(exe),*map(str,paths),'--metal-session-socket',str(path)],stdout=output,stderr=errors,env={**os.environ,**({'MTL_DEBUG_LAYER':'1'} if a.api_validation else {})})
  try:
   deadline=time.monotonic()+15
   while not path.exists():require(process.poll() is None and time.monotonic()<deadline,'Actual GPU server startup');time.sleep(.02)
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
    channel.settimeout(10);channel.connect(str(path))
    def read(n):
     b=bytearray()
     while len(b)<n:
      chunk=channel.recv(n-len(b));require(chunk,'Complete actual GPU reply');b+=chunk
     return bytes(b)
    def call(sid,op,payload=b'',error=0):
     seq=1 if not sid and op==0x140 else requests.get(sid,1)
     if sid or op==0x13b:requests[sid]=seq+1
     channel.sendall(struct.pack('<IHHIIQ',0x5550474e,3,op,len(payload),seq,sid)+payload)
     magic,version,operation,size,actual,session=struct.unpack('<IHHIIQ',read(24));require((magic,version,operation,actual,session)==(0x5550474e,3,op|0x8000,seq,sid) and 16<=size<=16*1024*1024+16,'Actual bounded GPU reply identity')
     status,reserved,handle=struct.unpack('<iIQ',read(16));body=read(size-16);require(status==error and not reserved,f'Actual operation {op:x} result {status}, expected {error}: {body[:160]!r}')
     observed.append(dict(session=sid,operation=op,error=status,handle=handle));return handle,body
    first=call(0,0x140)[0];second=call(0,0x140)[0]
    event,meta=call(first,0x133);meta=json.loads(meta);(OUT/'created-event-metadata.json').write_text(json.dumps(meta,indent=2)+'\n');require(meta['signaled_value']==0 and isinstance(meta['device_is_nil'],bool) and (meta['device_is_nil'] or meta['device_is_owner']),'Real new shared event initial value and actual nullable-device metadata')
    fence=call(first,0x128)[0]
    call(first,0x133,words(0),error=-2);call(first,0x134,words(fence),error=-2);call(first,0x134,words(0),error=-2);call(second,0x134,words(event),error=-2)
    label=b'actual-shared-event';require(json.loads(call(first,0x138,words(event,1,len(label))+label)[1])['label']==label.decode(),'Actual copied Metal label')
    call(first,0x138,words(event,2,0),error=-2);call(first,0x138,words(event,1,1)+b'\xff',error=-2);call(first,0x138,words(event,0,1)+b'x',error=-2)
    call(first,0x138,words(event,1,513)+b'x'*513,error=-2)
    notification=call(first,0x136,words(event,1))[0];future=call(first,0x136,words(event,99))[0]
    require(call(first,0x137,words(notification))[1]==words(0,0,0),'No fabricated notification before actual signal')
    call(first,0x136,words(fence,1),error=-2);call(second,0x137,words(notification),error=-2);call(first,0x137,words(0xffff),error=-2)
    exported,exportMeta=call(first,0x139,words(event));exportMeta=json.loads(exportMeta);require(exportMeta['label']==label.decode() and exportMeta['trace_id_supported'] and isinstance(exportMeta['trace_id'],int),'Actual exported MTLSharedEventHandle label and original-compatible trace getter')
    call(first,0x139,words(fence),error=-2);call(second,0x13a,words(0xffff),error=-2);call(second,0x13b,words(exported),error=-2)
    def texture(sid):
     handle,body=call(sid,0x12d,words(2,80,64,64,1,1,1,1,5,0,0,1));require(body==words(1),'Actual untracked GPU texture');return handle
    def render(sid,command,texture,color):return call(sid,0x107,words(command)+struct.pack('<3Q4d',texture,2,1,*color)+bytes(7*56))[0]
    def submit(sid,command):
     state=struct.unpack('<3Q',call(sid,0x12e,words(command))[1]);require(state[0] in (2,3,4),'Actual nonblocking submit status')
    def wait(sid,command):
     deadline=time.monotonic()+10
     while True:
      value=struct.unpack('<3Q',call(sid,0x12f,words(command))[1]);require(value[0] in (2,3,4),'Actual shared-event GPU state')
      if value[0]==4:require(0<value[1]<value[2],'Actual GPU completion timing');return
      require(value[1:]==(0,0) and time.monotonic()<deadline,'Only actual timed GPU completion succeeds');time.sleep(.001)
    def notify(sid,identifier,handle,value):
     deadline=time.monotonic()+5
     while True:
      ready,eventID,actual=struct.unpack('<3Q',call(sid,0x137,words(identifier))[1]);require(ready in (0,1),'Actual listener ready flag')
      if ready:require(eventID==handle and actual>=value,'Actual Metal listener event identity and counter');return actual
      require(eventID==actual==0 and time.monotonic()<deadline,'Pending is not a successful GPU notification');time.sleep(.001)
    library=call(first,0x102,bytes.fromhex(sha(paths[0])))[0]
    def function(name):return call(first,0x103,words(library)+name.encode().ljust(128,b'\0'))[0]
    vertex=function('read_surf_vert');fragment=function('attachment_clear_frag_lpf')
    pipeline=call(first,0x105,words(vertex,fragment,1,80,*([0]*7),15,*([0]*7)))[0]
    queue=call(first,0x101)[0];target=texture(first);command=call(first,0x106,words(queue))[0]
    encoder=render(first,command,target,(1,0,0,1));call(first,0x108,words(encoder,pipeline));call(first,0x109,words(encoder,0));call(first,0x10a,words(encoder,4,0,4,1));call(first,0x10b,words(encoder));call(first,0x131,words(command,event,1));submit(first,command);wait(first,command)
    require(call(first,0x10d,words(target,0,0,64,64,0))[1]==bytes(16384),'Original shader truly overrides contrasting GPU clear')
    require(call(first,0x134,words(event))[1]==words(1),'Actual GPU signal reaches shared-event value 1');notify(first,notification,event,1)
    require(call(first,0x137,words(future))[1]==words(0,0,0),'Never-signaled future listener stays pending')
    call(first,0x141);call(first,0x134,words(event),error=-2)
    imported,meta=call(second,0x13a,words(exported));meta=json.loads(meta);(OUT/'imported-event-metadata.json').write_text(json.dumps(meta,indent=2)+'\n');require(meta['signaled_value']==1 and isinstance(meta['device_is_nil'],bool) and (meta['device_is_nil'] or meta['device_is_owner']),'Actual Metal handle import survives owner namespace close with its actual device metadata')
    peerNotification=call(second,0x136,words(imported,2))[0];peerFuture=call(second,0x136,words(imported,99))[0]
    peerQueue=call(second,0x101)[0];peerTarget=texture(second);peerCommand=call(second,0x106,words(peerQueue))[0]
    call(second,0x132,words(peerCommand,imported,1));encoder=render(second,peerCommand,peerTarget,(0,0,1,1));call(second,0x10b,words(encoder));call(second,0x131,words(peerCommand,imported,2));submit(second,peerCommand);wait(second,peerCommand)
    blue=struct.pack('<I',0xff0000ff)*4096;require(call(second,0x10d,words(peerTarget,0,0,64,64,0))[1]==blue,'All peer GPU pixels after actual imported event wait')
    notify(second,peerNotification,imported,2);require(call(second,0x134,words(imported))[1]==words(2),'Actual imported GPU event reaches value 2')
    call(0,0x13b,words(exported));call(second,0x13a,words(exported),error=-2);call(0,0x13b,words(exported),error=-2)
    finalCommand=call(second,0x106,words(peerQueue))[0];call(second,0x132,words(finalCommand,imported,2));encoder=render(second,finalCommand,peerTarget,(0,1,0,1));call(second,0x10b,words(encoder));call(second,0x131,words(finalCommand,imported,3));submit(second,finalCommand);wait(second,finalCommand)
    green=struct.pack('<I',0xff00ff00)*4096;require(call(second,0x10d,words(peerTarget,0,0,64,64,0))[1]==green and call(second,0x134,words(imported))[1]==words(3),'Imported event survives actual export-handle release and runs more real GPU work')
    cpuEvent,_=call(second,0x133);cpuNotice=call(second,0x136,words(cpuEvent,7))[0]
    require(call(second,0x135,words(cpuEvent,7))[1]==words(7),'Separate actual CPU-set control; never used as GPU completion')
    notify(second,cpuNotice,cpuEvent,7);call(second,0x135,words(cpuEvent,6),error=-2)
    require(call(second,0x137,words(peerFuture))[1]==words(0,0,0),'No fabricated future notification during peer execution')
    call(second,0x141)
   require(process.wait(timeout=10)==0,'Actual shared-event host finishes after contexts and exports close')
  finally:
   if process.poll() is None:
    try:process.wait(timeout=2)
    except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=5)
d=json.loads((OUT/'host-report.json').read_text());refusals=sum(bool(row['error']) for row in observed);require(refusals==18,'All eighteen genuine refusal controls execute')
require(d['transport_healthy'] and d['session_finished'] and d['opened_sessions']==d['closed_sessions']==2 and not d['live_shared_exports'] and not d['pending_submissions'] and not d['failed_commands'] and not d['aborted_encoders'],'Actual contexts, exported handles and submitted work close normally')
require(len(d['completed_commands'])==len(d['submitted_commands'])==3 and all(row['actual_status'] in (2,3,4) and not row['wait_until_completed_called'] for row in d['submitted_commands']),'Three actual nonblocking GPU tasks and valid completion timing')
require([row['sha256'] for row in d['texture_readbacks']]==[hashlib.sha256(bytes(16384)).hexdigest(),hashlib.sha256(blue).hexdigest(),hashlib.sha256(green).hexdigest()] and not d['texture_uploads'],'All 12288 actual original-shader/peer pixels, no CPU-generated texture data')
notices=d['shared_event_notifications'];require(len(notices)==5 and sum(row['actually_fired'] for row in notices)==3 and all(row['actual_value']==0 for row in notices if not row['actually_fired']),'Three real Metal listener callbacks and two cancelled pending registrations; never manufactured notification success')
require([row['operation'] for row in d['shared_event_exports']]==['export','import','drop'],'Actual newSharedEventHandle/newSharedEventWithHandle lifetimes and one final export release')
require(len(d['event_operations'])==5 and all(row['shared'] for row in d['event_operations']) and [row['value'] for row in d['event_operations']]==[1,1,2,2,3],'Actual shared GPU timeline signals and waits across imported objects')
sets=[row for row in d['shared_event_values'] if row['cpu_set']];require(len(sets)==1 and sets[0]['event']==cpuEvent and sets[0]['value']==7 and all(row['event']!=cpuEvent for row in d['event_operations']),'Only separate CPU control uses real setter; none of the rendered GPU dependencies is synthesized on CPU')
lines=(OUT/'host-stderr.log').read_text().splitlines();reported=[]
for line in lines:
 if not line or line=='OFFLINE_METAL_READY' or line.endswith('Metal API Validation Enabled'):continue
 match=re.fullmatch(r'OFFLINE_METAL_ERROR request=(\d+) operation=(\d+) error=(-?\d+)\s*',line);require(match is not None,'Unexpected actual GPU validation output: '+line);reported.append(tuple(map(int,match.groups())))
require(reported==[(row['request'],row['operation'],row['error']) for row in d['operations'] if row['error']],'All diagnostics correspond to actual expected refusals')
if a.api_validation:require(any(line.endswith('Metal API Validation Enabled') for line in lines),'Actual API validation enabled')
(OUT/'checkpoint.json').write_text(json.dumps(dict(process_sha256=sha(exe),report_sha256=sha(OUT/'host-report.json'),actual_gpu_commands=3,actual_gpu_event_calls=5,pixels_checked=12288,actual_listener_callbacks=3,cancelled_unfired_listeners=2,refusals=refusals,actual_export_handle_survives_owner_close=True,actual_import_survives_export_release=True,actual_export_metadata=exportMeta,native_mach_rights_qualified=False,original_desktop=False,adreno_execution=False),indent=2)+'\n')
print('PASS: actual shared GPU values/listeners and Metal handle import after owner close; all 12288 pixels and',refusals,'refusals')
print('Host-only internal handle transport; native Mach capability delegation is not qualified')
