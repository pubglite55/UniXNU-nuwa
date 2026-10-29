#!/usr/bin/env python3
"""Execute genuine asynchronous GPU submission/status and completion-safe teardown."""
import argparse,hashlib,json,os,re,socket,struct,subprocess,tempfile,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--disconnect-control',action='store_true');p.add_argument('--api-validation',action='store_true');a=p.parse_args()
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/('build/host-metal-async-disconnect' if a.disconnect_control else 'build/host-metal-async');OUT.mkdir(exist_ok=True)
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
     seq=requests.get(sid,1)
     if sid:requests[sid]=seq+1
     channel.sendall(struct.pack('<IHHIIQ',0x5550474e,3,op,len(payload),seq,sid)+payload)
     magic,version,operation,size,actual,session=struct.unpack('<IHHIIQ',read(24));require((magic,version,operation,actual,session)==(0x5550474e,3,op|0x8000,seq,sid) and 16<=size<=16*1024*1024+16,'Actual bounded GPU reply identity')
     status,reserved,handle=struct.unpack('<iIQ',read(16));body=read(size-16);require(status==error and not reserved,f'Actual operation {op:x} result {status}, expected {error}: {body[:160]!r}')
     observed.append(dict(session=sid,operation=op,error=status,handle=handle));return handle,body
    first=call(0,0x140)[0];second=call(0,0x140)[0]
    fence=call(first,0x128)[0];foreign=call(second,0x128)[0];unused=call(first,0x128)[0]
    event=call(first,0x130)[0];unusedEvent=call(first,0x130)[0];foreignEvent=call(second,0x130)[0];call(first,0x130,words(0),error=-2)
    queue=call(first,0x101)[0];otherQueue=call(first,0x101)[0]
    def texture(private=False):
     handle,body=call(first,0x12d,words(2,80,64,64,1,1,1,1,5,2 if private else 0,0,1));require(body==words(1),'Actual explicitly untracked texture mode');return handle
    source=texture(True);shared=texture();outputTexture=texture();destination=texture()
    library=call(first,0x102,bytes.fromhex(sha(paths[0])))[0]
    def function(name):return call(first,0x103,words(library)+name.encode().ljust(128,b'\0'))[0]
    vertex=function('read_surf_vert');fragment=function('read_surf_frag')
    pipeline=call(first,0x105,words(vertex,fragment,1,80,*([0]*7),15,*([0]*7)))[0]
    command=call(first,0x106,words(queue))[0]
    def render(command,texture,color):return call(first,0x107,words(command)+struct.pack('<3Q4d',texture,2,1,*color)+bytes(7*56))[0]
    encoder=render(command,source,(1,0,0,1));call(first,0x131,words(command,event,1),error=-2)
    call(first,0x129,words(encoder,fence,0),error=-2);call(first,0x129,words(encoder,fence,4),error=-2)
    call(first,0x129,words(encoder,foreign,2),error=-2);call(first,0x12b,words(encoder,fence,0),error=-2)
    call(first,0x12a,words(encoder,unused,3),error=-4);call(first,0x129,words(encoder,fence,2))
    call(first,0x12a,words(encoder,fence,3),error=-4);call(first,0x10b,words(encoder))
    call(first,0x129,words(encoder,fence,2),error=-2)
    def copy(encoder,src,dst):return words(encoder,src,dst,0,0,0,0,0,64,64,1,0,0,0,0,0)
    blit=call(first,0x117,words(command))[0]
    call(first,0x12c,words(blit,fence,1),error=-2);call(first,0x12c,words(blit,fence,0))
    call(first,0x122,copy(blit,source,shared));call(first,0x12b,words(blit,fence,0));call(first,0x10b,words(blit))
    encoder=render(command,outputTexture,(1,1,1,1));call(first,0x12a,words(encoder,fence,3))
    call(first,0x108,words(encoder,pipeline));call(first,0x109,words(encoder,0));call(first,0x11b,words(encoder,shared,0));call(first,0x10a,words(encoder,4,0,4,1))
    call(first,0x129,words(encoder,fence,3));call(first,0x10b,words(encoder))
    call(first,0x131,words(command,event,0),error=-2);call(first,0x131,words(command,fence,1),error=-2);call(first,0x131,words(command,foreignEvent,1),error=-2)
    call(first,0x131,words(command,event,1));call(first,0x131,words(command,event,1),error=-2);call(first,0x132,words(command,event,1),error=-4)
    preWaiter=call(first,0x106,words(otherQueue))[0];call(first,0x132,words(preWaiter,unusedEvent,1),error=-4);call(first,0x132,words(preWaiter,event,1),error=-4)
    call(first,0x12f,words(command),error=-2)
    firstSubmit=struct.unpack('<3Q',call(first,0x12e,words(command))[1]);require(firstSubmit[0] in (2,3,4),'Actual submitted command status')
    call(first,0x12e,words(command),error=-2);call(first,0x10c,words(command),error=-2);call(second,0x12f,words(command),error=-2)
    call(first,0x12f,words(queue),error=-2);call(first,0x12f,b'',error=-2)
    call(first,0x131,words(command,event,2),error=-2);call(first,0x132,words(preWaiter,event,2),error=-4)
    expected=words(0xffff0000)[:4]*4096
    
    secondCommand=call(first,0x106,words(otherQueue))[0];call(first,0x132,words(secondCommand,event,1));blit=call(first,0x117,words(secondCommand))[0]
    call(first,0x132,words(secondCommand,event,1),error=-2);call(first,0x122,copy(blit,outputTexture,destination));call(first,0x10b,words(blit));call(first,0x131,words(secondCommand,event,2))
    secondSubmit=struct.unpack('<3Q',call(first,0x12e,words(secondCommand))[1]);require(secondSubmit[0] in (2,3,4),'Actual second submitted queue status')
    def wait(command):
     deadline=time.monotonic()+10
     while True:
      actual=struct.unpack('<3Q',call(first,0x12f,words(command))[1]);require(actual[0] in (2,3,4),'Actual GPU status range')
      if actual[0]==4:require(0<actual[1]<actual[2],'Real completed GPU timing');return
      require(actual[1:]==(0,0) and time.monotonic()<deadline,'Unavailable completion times remain zero; bounded actual GPU wait');time.sleep(.001)
    wait(command);wait(secondCommand);wait(command)
    require(call(first,0x10d,words(outputTexture,0,0,64,64,0))[1]==expected,'All original shader pixels after actual asynchronous GPU completion')
    actualPixels=call(first,0x10d,words(destination,0,0,64,64,0))[1];(OUT/'actual-destination.bin').write_bytes(actualPixels)
    from collections import Counter
    (OUT/'readback-observation.json').write_text(json.dumps(dict(expected_sha256=hashlib.sha256(expected).hexdigest(),actual_sha256=hashlib.sha256(actualPixels).hexdigest(),pixel_words=Counter(hex(p[0]) for p in struct.iter_unpack('<I',actualPixels))),indent=2)+'\n')
    require(actualPixels==expected,'All pixels copied on actual second GPU queue')
    pending=call(first,0x106,words(queue))[0];encoder=render(pending,destination,(0,0,1,1));call(first,0x129,words(encoder,unused,2));call(first,0x10b,words(encoder))
    waiter=call(first,0x106,words(otherQueue))[0];blit=call(first,0x117,words(waiter))[0]
    call(first,0x12c,words(blit,unused,0),error=-4)
    call(first,0x10e,words(fence));call(first,0x12c,words(blit,fence,0),error=-2);call(first,0x10b,words(blit))
    call(first,0x12d,words(2,80,64,64,1,1,1,1,5,0,0,3),error=-2);call(first,0x128,words(0),error=-2)
    closingCommand=call(first,0x106,words(queue))[0];call(first,0x132,words(closingCommand,event,2));encoder=render(closingCommand,outputTexture,(0,1,0,1));call(first,0x10b,words(encoder));call(first,0x131,words(closingCommand,event,3))
    closingSubmit=struct.unpack('<3Q',call(first,0x12e,words(closingCommand))[1]);require(closingSubmit[0] in (2,3,4),'Actual submission before independent reference release')
    call(first,0x10e,words(closingCommand));call(first,0x12f,words(closingCommand),error=-2)
    if not a.disconnect_control:call(first,0x141);call(second,0x141)
   require(process.wait(timeout=10)==(2 if a.disconnect_control else 0),'Actual transport outcome remains failure on disconnect')
  finally:
   if process.poll() is None:
    try:process.wait(timeout=2)
    except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=5)
d=json.loads((OUT/'host-report.json').read_text());refusals=sum(bool(r['error']) for r in observed)
lines=(OUT/'host-stderr.log').read_text().splitlines();reported=[]
for line in lines:
 if not line or line=='OFFLINE_METAL_READY' or line.endswith('Metal API Validation Enabled'):continue
 match=re.fullmatch(r'OFFLINE_METAL_ERROR request=(\d+) operation=(\d+) error=(-?\d+)\s*',line)
 require(match is not None,'Unexpected actual host/Metal API validation output: '+line)
 reported.append(tuple(map(int,match.groups())))
require(reported==[(r['request'],r['operation'],r['error']) for r in d['operations'] if r['error']],'Every stderr refusal binds the corresponding genuine operation; no unaccounted GPU validation errors')
if a.api_validation:require(any(l.endswith('Metal API Validation Enabled') for l in lines),'Actual Metal API validation acknowledgement')
require(d['transport_healthy']==(not a.disconnect_control) and d['session_finished']==(not a.disconnect_control) and d['opened_sessions']==2 and d['closed_sessions']==(0 if a.disconnect_control else 2) and not d['aborted_encoders'] and not d['open_encoders'] and not d['pending_enqueues'],'Actual namespaces close, including unsubmitted pending/waiter controls, without any cleanup-created submission')
require(len(d['completed_commands'])==3 and len(d['fences_created'])==3 and len(d['fence_operations'])==6 and len(d['texture_readbacks'])==2 and refusals==31,'Exact actual fence calls, three GPU submissions and two readbacks and thirty-one genuine refusal controls')
require(len(d['texture_hazard_modes'])==4 and all((r['requested'],r['actual'])==(1,1) for r in d['texture_hazard_modes']),'All four resources actually untracked by real Metal')
require(all(r['sha256']==hashlib.sha256(expected).hexdigest() for r in d['texture_readbacks']) and not d['texture_uploads'] and not d['cpu_pixel_renderer'] and not d['adreno_execution'] and not d['original_desktop'],'All 8192 pixels independently verified; source clear/copies/shader run only on real host GPU')
require(len(d['submitted_commands'])==3 and all(not r['wait_until_completed_called'] and r['actual_status'] in (2,3,4) for r in d['submitted_commands']) and any(r['actual_status']<4 for r in d['submitted_commands']),'Actual nonblocking submit observed before GPU completion, never a CPU-synthesized status')
require(not d['pending_submissions'] and not d['failed_commands'] and len({r['command'] for r in d['completed_commands']})==3 and all(r['status']==4 and 0<r['gpu_start_ns']<r['gpu_end_ns'] for r in d['completed_commands']),'Actual completions are unique, fully timed and quiesced before session release')
require(next(r for r in d['completed_commands'] if r['command']==closingCommand)['observed_by']==('transport-lost' if a.disconnect_control else 'session-close') and all(r['command'] not in (pending,waiter) for r in d['completed_commands']),'Released but actually submitted command completes during close; unsubmitted controls never acquire GPU submissions')
require(len(d['events_created'])==3 and len(d['event_operations'])==5 and [(r['signal'],r['value']) for r in d['event_operations']]==[(True,1),(False,1),(True,2),(False,2),(True,3)] and all(r['event']==event and r['session']==first for r in d['event_operations']) and all(r['actual_producer_status'] in (2,3,4) for r in d['event_operations'] if not r['signal']),'Actual GPU timeline event signals/waits across both real queues; CPU never reports a signaled value')
require(d['command_observations'] and all(r['actual_status'] in (2,3,4) for r in d['command_observations']),'Only real status observations returned')
(OUT/'checkpoint.json').write_text(json.dumps(dict(process_sha256=sha(exe),report_sha256=sha(OUT/'host-report.json'),operations=len(observed),api_validation=a.api_validation,actual_gpu_commands=3,actual_nonblocking_submissions=3,actual_fence_calls=6,actual_gpu_event_calls=5,refusals=refusals,explicit_untracked_resources=4,pixels_checked=8192,pending_producer_refused=True,same_encoder_cycle_refused=True,cross_queue_gpu_event_dependency=True,asynchronous_wait_before_producer=False,actual_completion_on_close=not a.disconnect_control,actual_transport_loss=a.disconnect_control,guest_kernel_broker=False,original_desktop=False,adreno_execution=False),indent=2)+'\n')
print('PASS: actual asynchronous GPU submissions/status, cross-queue GPU event dependency and completion-safe '+('transport-loss failure' if a.disconnect_control else 'close')+'; all 8192 pixels and thirty-one refusal controls')
