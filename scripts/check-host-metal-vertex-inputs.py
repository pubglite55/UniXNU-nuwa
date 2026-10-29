#!/usr/bin/env python3
"""Run original QuartzCore vertex attributes through real GPU pipelines and buffers."""
import hashlib,json,os,socket,struct,subprocess,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'build/host-metal-vertex-inputs';OUT.mkdir(exist_ok=True)
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
  process=subprocess.Popen([str(exe),*map(str,paths),'--metal-session-socket',str(path)],stdout=output,stderr=errors,env={**os.environ,'MTL_DEBUG_LAYER':'1'})
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
    library=call(first,0x102,bytes.fromhex(sha(paths[0])))[0]
    def function(name):return call(first,0x103,words(library)+name.encode().ljust(128,b'\0'))[0]
    vertex=function('std_vert0_lpf');fragment=function('attachment_clear_frag_lpf')
    # Exact static vertex descriptor: position float4, texcoord float2 and color
    # float4. Original std_vert0_lpf reads MVP from buffer(2), not generated code.
    packet=[vertex,fragment,1,80,*([0]*7),15,*([0]*7)]+[0]*58
    require(len(packet)==77,'Independent original attachment-prefix byte size')
    packet += [0]*186
    for index,fmt,offset in ((0,31,0),(1,29,16),(3,31,24)):packet[77+3*index:80+3*index]=[fmt,offset,0]
    packet[170:173]=[40,1,1]
    require(len(words(*packet))==2104,'Independent fixed vertex-layout transport size')
    # Refuse before pipeline creation; every control is followed by the valid
    # request, so no failed request can poison another namespace or descriptor.
    controls=[]
    for index,value in ((77,43),(79,31),(78,4096),(170,(1<<64)-1),(171,3),(172,0),(173,1)):
     invalid=packet.copy();invalid[index]=value;controls.append(invalid)
    inactive=packet.copy();inactive[77:170]=[0]*93;inactive[170:173]=[0]*3;controls.append(inactive)
    for invalid in controls:call(first,0x126,words(*invalid),error=-2)
    call(first,0x126,words(*packet)[:-8],error=-2)
    call(second,0x126,words(*packet),error=-2)
    pipeline=call(first,0x126,words(*packet))[0]
    # Mutating caller storage after successful creation must not change the
    # actual already-created host pipeline descriptor.
    packet[77]=0
    queue=call(first,0x101)[0];texture=call(first,0x104,words(2,80,64,64,1,1,1,1,5,0,0))[0]
    positions=[(-1,-1),(0,-1),(-1,1),(0,1)]
    vertices=b''.join(struct.pack('<10f',x,y,0,1,0,0,0,1,0,1) for x,y in positions)
    identity=struct.pack('<16f',1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1)
    def buffer(data):
     h=call(first,0x111,words(len(data),0))[0];call(first,0x112,words(h,0,len(data))+data);return h
    vertexBuffer=buffer(vertices);matrixBuffer=buffer(identity)
    pixels=[]
    for iteration in range(2):
     if iteration:
      # Real buffer upload changes vertex coverage to the other half.
      changed=b''.join(struct.pack('<10f',x+1,y,0,1,0,0,1,0,0,1) for x,y in positions)
      call(first,0x112,words(vertexBuffer,0,len(changed))+changed)
     command=call(first,0x106,words(queue))[0]
     encoder=call(first,0x107,words(command)+struct.pack('<3Q4d',texture,2,1,1,0,0,1)+bytes(7*56))[0]
     call(first,0x108,words(encoder,pipeline));call(first,0x109,words(encoder,0))
     call(first,0x114,words(encoder,vertexBuffer,0,0));call(first,0x114,words(encoder,matrixBuffer,0,2))
     call(first,0x10a,words(encoder,4,0,4,1));call(first,0x10b,words(encoder))
     status=struct.unpack('<3Q',call(first,0x10c,words(command))[1]);require(status[0]==4 and 0<status[1]<status[2],'Real original vertex/fragment GPU completion and timing')
     actual=call(first,0x10d,words(texture,0,0,64,64,0))[1]
     black=bytes(4);red=bytes((0,0,255,255))
     expected=((black*32+red*32) if not iteration else (red*32+black*32))*64
     require(actual==expected,'Every pixel follows actual original vertex attributes and updated GPU buffer geometry')
     pixels.append(hashlib.sha256(actual).hexdigest())
    call(first,0x141);call(second,0x141)
   require(process.wait(timeout=10)==0,'Actual GPU server closes cleanly')
  finally:
   if process.poll() is None:process.terminate();process.wait(timeout=5)
d=json.loads((OUT/'host-report.json').read_text());rows=d['vertex_pipelines']
require(d['transport_healthy'] and d['session_finished'] and d['opened_sessions']==d['closed_sessions']==2 and len(rows)==1 and len(d['completed_commands'])==2,'Actual isolated namespaces, one real vertex pipeline and two actual GPU submissions')
require(rows[0]['vertex']=='std_vert0_lpf' and rows[0]['fragment']=='attachment_clear_frag_lpf' and rows[0]['attributes']==[dict(index=i,format=f,offset=o,buffer=0) for i,f,o in ((0,31,0),(1,29,16),(3,31,24))] and rows[0]['layouts']==[dict(index=0,stride=40,step=1,rate=1)],'Actual host Metal descriptor roundtrip matches exact original vertex input layout')
require(len(d['texture_readbacks'])==2 and [r['sha256'] for r in d['texture_readbacks']]==pixels and not d['texture_uploads'] and not d['cpu_pixel_renderer'] and not d['adreno_execution'] and not d['original_desktop'],'Two complete real GPU images without pixel uploads, software drawing or deployment claims')
errors=(OUT/'host-stderr.log').read_text();require(not any(v in errors for v in ('Validation Error','assertion failed','failed assertion','failed validation','Execution of the command buffer was aborted')),'Actual Metal API Validation stays clean')
(OUT/'checkpoint.json').write_text(json.dumps(dict(process_sha256=sha(exe),backend_sources=build['backend_sources'],report_sha256=sha(OUT/'host-report.json'),api_validation=True,original_vertex='std_vert0_lpf',original_fragment='attachment_clear_frag_lpf',actual_gpu_submissions=2,pixels_checked=8192,pixel_sha256=pixels,refusals=sum(bool(r['error']) for r in observed),native_frontend_tested=False,original_desktop=False,adreno_execution=False,active_native_adreno_4k=False),indent=2)+'\n')
print('PASS: original QuartzCore vertex inputs, real MVP/buffer bindings and two GPU geometry updates; all 8192 pixels and ten refusal controls')
