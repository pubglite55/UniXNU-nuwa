#!/usr/bin/env python3
"""Pin original provider startup dependencies; do not run the Apple GPU driver."""
import hashlib,json,runpy,struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
provider=runpy.run_path(str(ROOT/'scripts/audit-target-iogpu-provider.py'));n=provider['n']
read,require,adrp=n['read'],n['require'],n['adrp']
abi=json.loads((ROOT/'build/gpu-analysis/original-iogpu-provider-abi.json').read_text())
start=abi['start'];body=read(start,abi['start_bytes']);words=struct.unpack('<'+'I'*(len(body)//4),body)
require(hashlib.sha256(body).hexdigest()==abi['start_sha256'],'Exact whole original start body')

def branch(pc,word):
 require(word&0x7c000000==0x14000000,'Actual direct B/BL')
 imm=word&0x3ffffff
 return pc+4*(imm-(1<<26) if imm&(1<<25) else imm)

def target(pc,word):
 dest=branch(pc,word);a,b,c=struct.unpack('<3I',read(dest,12))
 if a&0x9f00001f==0x90000010 and b&0xffc003ff==0xf9400210 and c==0xd61f0200:return n['imported'](dest)
 return dest

def string(pc,a,b):
 require(a&0x9f000000==0x90000000 and b&0xffc00000==0x91000000 and (b>>5)&31==a&31,'Actual ADRP/ADD string reference')
 return read(adrp(pc,a)+((b>>10)&4095),160).split(b'\0')[0].decode()

direct=[];strings={};metas={}
for i,w in enumerate(words):
 pc=start+i*4
 if w&0xfc000000==0x94000000:
  dest=target(pc,w);direct.append(dict(pc=pc,target=dest,names=sorted(name for name,a in n['names'].items() if a==dest)))
 if i+1==len(words) or w&0x9f000000!=0x90000000:continue
 following=words[i+1]
 if following&0xffc00000==0x91000000 and (following>>5)&31==w&31:
  try:value=string(pc,w,following)
  except (ValueError,UnicodeError):continue
  if value and all(c.isprintable() for c in value):strings[pc]=value
 if following&0xffc00000==0xf9400000 and (following>>5)&31==w&31:
  value=struct.unpack('<Q',read(adrp(pc,w)+((following>>10)&4095)*8,8))[0]
  names=sorted(name for name,a in n['names'].items() if a==value)
  if names:metas[pc]=names

model=[pc for pc,v in strings.items() if v=='model']
require(len(model)==1,'Unique provider model property reference')
at=(model[0]-start)//4
require(words[at-2:at]==(0xf9400008,0xf940a508) and words[at+2]==0xd63f0100,'Actual provider copyProperty virtual slot 41')
require(metas[start+4*(at+4)]==['__ZN6OSData9metaClassE'],'Actual model value must pass original OSData metaclass cast')
casts=[d for d in direct if '__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass' in d['names']]
require(any(d['pc']==start+4*(at+7) for d in casts),'Actual model OSData cast is executed')
compare=next(i for i in range(at+6,at+20) if words[i]==0x713ff81f)
conditional=words[compare+1];require(conditional&0xff00001f==0x54000008,'Actual unsigned higher-than-4094 branch')
imm=(conditional>>5)&0x7ffff;clamp=compare+1+(imm-(1<<19) if imm&(1<<18) else imm)
require(words[clamp]==0x5281fff7,'Oversized model data is clamped to 4095 before its NUL byte')

surface=[pc for pc,v in strings.items() if v=='IOCoreSurfaceRoot']
require(len(surface)==1,'Unique actual IOSurface root service name')
at=(surface[0]-start)//4
require(words[at+2]==0xd2800001 and target(start+4*(at+3),words[at+3])==n['names']['__ZN9IOService12nameMatchingEPKcP12OSDictionary'],'Actual nameMatching with NULL dictionary')
require(words[at+5]==0x92800001 and target(start+4*(at+6),words[at+6])==n['names']['__ZN9IOService22waitForMatchingServiceEP12OSDictionaryy'],'Actual original IOSurface wait uses UINT64_MAX nanoseconds')

# The later configuration callback receives the actual private output at +488.
dispatch=next(d for d in abi['self_virtual_dispatches'] if d['slot']==192)
at=(dispatch['pc']-start)//4
require(words[at-1]==0x9107a276 and words[at+2:at+5]==(0xaa1303e0,0xaa1603e1,0xd63f0100),'Actual output x1=this+488, no guessed private source type')
require(any('__ZN10IOWorkLoop8workLoopEv' in d['names'] for d in direct),'Original startup also allocates an actual workloop')

# Inspect only this supplied image's concrete Apple implementation to qualify
# the abstract callback layout. It will never be loaded as an Adreno backend.
from native_prelink import macho,backed_offset,unserialize_xml,exports
kernel=ROOT/'.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed'
raw=kernel.read_bytes();require(hashlib.sha256(raw).hexdigest()==n['plan']['original_sha256'],'Exact supplied original kernelcache')
image=macho(raw);segments=image['segments']
def original_read(address,size):
 offset=backed_offset(segments,address,size,len(raw));return raw[offset:offset+size]
info=next(s for s in segments if s['name']=='__PRELINK_INFO')
entries={e['CFBundleIdentifier']:e for e in unserialize_xml(original_read(info['va'],info['filesize']))['_PrelinkInfoDictionary']}
entry=entries['com.apple.AGXG9G'];offset=backed_offset(segments,entry['_PrelinkExecutableLoadAddr'],32,len(raw));module=macho(raw,offset)
text=next(s for s in module['segments'] if s['name']=='__TEXT_EXEC');code=original_read(text['va'],text['filesize'])
original_names={name:a for a,group in exports(raw,image).items() for name in group}
constructor=original_names['__ZN11OSMetaClassC2EPKcPKS_j']

def original_target(pc,word):
 dest=branch(pc,word);a,b,c=struct.unpack('<3I',original_read(dest,12))
 require(a&0x9f00001f==0x90000010 and b&0xffc003ff==0xf9400210 and c==0xd61f0200,'Original class initializer calls a genuine import stub')
 return struct.unpack('<Q',original_read(adrp(dest,a)+((b>>10)&4095)*8,8))[0]

classes=[]
for i in range(8,len(code)-24,4):
 pc=text['va']+i;a,b,c,d,e,f=struct.unpack_from('<6I',code,i)
 if a&0x9f00001f!=0x90000001 or b&0xffc003ff!=0x91000021 or c&0x9f00001f!=0x90000002 or e&0xffe0001f!=0x52800003 or f&0xfc000000!=0x94000000:continue
 if d&0xffc003ff not in (0x91000042,0xf9400042):continue
 if original_target(pc+20,f)!=constructor:continue
 x,y=struct.unpack_from('<2I',code,i-8)
 require(x&0x9f00001f==0x90000000 and y&0xffc003ff==0x91000000,'Original metadata object is directly derived')
 meta=adrp(pc-8,x)+((y>>10)&4095);name=original_read(adrp(pc,a)+((b>>10)&4095),128).split(b'\0')[0].decode()
 parent=adrp(pc+8,c)+((d>>10)&4095)*(8 if d&0xffc00000==0xf9400000 else 1)
 if d&0xffc00000==0xf9400000:parent=struct.unpack('<Q',original_read(parent,8))[0]
 classes.append(dict(name=name,metaclass=meta,parent=parent,instance_bytes=(e>>5)&65535,initializer=pc-8))
name=entry['IOKitPersonalities']['AGXG9G_A0']['IOClass'];found=[c for c in classes if c['name']==name]
require(len(found)==1,'Unique original target personality/concrete class initializer')
concrete=found[0];chain=[concrete];by_meta={c['metaclass']:c for c in classes}
while chain[-1]['parent'] in by_meta:chain.append(by_meta[chain[-1]['parent']])
require(chain[-1]['parent']==abi['metaclass']-n['plan']['slide'],'Actual concrete class ancestry reaches original IOGPU')
getters=[]
for i in range(0,len(code)-12,4):
 pc=text['va']+i;a,b,c=struct.unpack_from('<3I',code,i)
 if a&0x9f00001f==0x90000000 and b&0xffc003ff==0x91000000 and c==0xd65f03c0 and adrp(pc,a)+((b>>10)&4095)==concrete['metaclass']:getters.append(pc)
require(len(getters)==1,'Unique real concrete getMetaClass')
tables=[]
for segment in module['segments']:
 if segment['name'] in ('__TEXT_EXEC','__LINKEDIT'):continue
 data=original_read(segment['va'],segment['filesize']);at=0
 while True:
  pos=data.find(struct.pack('<Q',getters[0]),at)
  if pos<0:break
  at=pos+1;vp=segment['va']+pos-56
  if vp%8:continue
  values=struct.unpack('<512Q',original_read(vp,4096));count=next(i for i,v in enumerate(values) if not v)
  if count>=215:tables.append((vp,values[:count]))
require(len(tables)==1,'Unique genuine concrete provider table')
vp,values=tables[0]
hooks={}
for slot in abi['pure_virtual_slots']:
 address=values[slot]
 require(text['va']<=address<text['va']+text['filesize'],'Concrete required hook actually resides in original vendor executable')
 hooks[slot]=dict(address=address,entry_32_sha256=hashlib.sha256(original_read(address,32)).hexdigest())
config=values[192];end=min(v for v in values if v>config);config_body=original_read(config,end-config)
require(struct.pack('<I',0xaa0103f4) in config_body and struct.pack('<I',0xb9008688) in config_body,'Concrete config hook preserves actual output and can write through +132')
require(struct.pack('<I',0xf9441908) in config_body,'Concrete config also dispatches a further own virtual at slot 262')
# The original wrapper delegates to the common configureDevice body. Its own
# assertion embeds the exact source signature; an older device's symbol hints
# are not used to name or qualify this target's method.
first=values[195];wrapper=original_read(first,min(v for v in values if v>first)-first)
calls=[branch(first+i,w) for i in range(0,len(wrapper),4) if (w:=struct.unpack_from('<I',wrapper,i)[0])&0xfc000000==0x94000000]
require(len(calls)==1,'Concrete first required hook has exactly one original common delegation')
common=calls[0];common_end=values[196]
require(text['va']<=common<common_end<text['va']+text['filesize'],'Common configuration body has an actual adjacent virtual entry bound')
common_body=original_read(common,common_end-common);configuration_strings={}
for i in range(0,len(common_body)-8,4):
 pc=common+i;a,b=struct.unpack_from('<2I',common_body,i)
 if a&0x9f000000!=0x90000000 or b&0xffc00000!=0x91000000 or (b>>5)&31!=a&31:continue
 try:value=original_read(adrp(pc,a)+((b>>10)&4095),220).split(b'\0')[0].decode()
 except (ValueError,UnicodeError):continue
 if value and all(c.isprintable() for c in value):configuration_strings[pc]=value
signature='virtual bool AGXAccelerator::configureDevice(IOService *)'
require(signature in configuration_strings.values(),'Exact supplied concrete implementation names the required Boolean callback')
require({'interrupts','interrupts-valid','RGXRegs','FenderRegs'}<=set(configuration_strings.values()),'Original configureDevice includes real interrupt and hardware mapping configuration')

initializers=[d for d in direct if model[0]<d['pc']<dispatch['pc'] and n['text']['va']<=d['target']<start]
require(len(initializers)==1,'Unique private default-config initializer before required config output')
defaults=initializers[0]['target'];before_start=read(defaults,start-defaults)
end_default=next(i+4 for i in range(0,len(before_start),4) if struct.unpack_from('<I',before_start,i)[0]==0xd65f03c0)
validator=defaults+end_default;validation=read(validator,start-validator)
validation_words=struct.unpack('<'+'I'*(len(validation)//4),validation)
require(validation_words[3:5]==(0xf940f408,0xb40002c8) and validation_words[5:7]==(0xb9420008,0x34000428) and validation_words[7:9]==(0xb9423c08,0x34000588) and validation_words[9:12]==(0xb9426408,0x7100251f,0x540006c3),'Actual validation loads/checks config name, channel count, wait timeout and scheduler priority count')
requirements=[dict(name='accelName',offset=0,bytes=8,condition='non-null pointer'),dict(name='numEventChannels',offset=24,bytes=4,condition='nonzero'),dict(name='waitForGPUTimeoutSeconds',offset=84,bytes=4,condition='nonzero'),dict(name='maxSchedulerPriorityCount',offset=124,bytes=4,condition='at most 8')]
diagnostics=[]
for i in range(0,len(validation)-8,4):
 pc=validator+i;a,b=struct.unpack_from('<2I',validation,i)
 if a&0x9f00001f==0x90000003 and b&0xffc003ff==0x91000063:diagnostics.append(string(pc,a,b))
require(len(diagnostics)==4 and all(any(r['name'] in v for v in diagnostics) for r in requirements),'Actual original diagnostics independently identify all four field meanings')
report=dict(original_kernel_sha256=hashlib.sha256(raw).hexdigest(),reference_candidate_sha256=n['plan']['candidate_sha256'],original_start_sha256=abi['start_sha256'],provider_model_type='OSData',model_direct_length_threshold=4094,model_max_data_bytes=4095,model_output_includes_nul=True,iosurface_match='IOCoreSurfaceRoot',iosurface_wait_timeout_ns=(1<<64)-1,required_config_slot=192,required_config_output_offset=488,concrete_apple_class_chain=chain,concrete_table=vp,concrete_table_entries=len(values),concrete_required_hooks=hooks,concrete_config_range_end=end,concrete_config_body_sha256=hashlib.sha256(config_body).hexdigest(),concrete_config_writes_at_least_bytes=136,concrete_config_additional_slot=262,first_required_callback_source_signature=signature,common_configuration_body_sha256=hashlib.sha256(common_body).hexdigest(),common_configuration_strings=configuration_strings,original_config_validator=validator,original_config_validator_sha256=hashlib.sha256(validation).hexdigest(),config_required_fields=requirements,direct_calls=direct,string_references=strings,private_source_struct_recovered=False,concrete_apple_driver_executed=False,successful_native_provider_start=False,normal_system_publication=False,adreno_execution=False,active_native_adreno_4k=False,original_desktop=False)
(ROOT/'build/gpu-analysis/original-iogpu-start-contract.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: original model bound, IOSurface dependency, configureDevice signature, concrete ancestry and four actual config validation fields')
print('Source analysis only; opaque private config is not qualified by zero filling or copying Apple capabilities to Adreno')
