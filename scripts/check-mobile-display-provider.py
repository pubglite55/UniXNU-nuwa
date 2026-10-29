#!/usr/bin/env python3
"""Check actual original-client queries against the initial native display provider."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'build/gop-framebuffer'
sys.path.insert(0,str(ROOT/'kits/XnuPrelink'))
from native_prelink import macho,exports,backed_offset
def require(v,why):
    if not v:raise SystemExit(why)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
build=json.loads((OUT/'build-report.json').read_text())
revision=build['kit_revision']
for name in ('NativeMobileDisplay.cpp','OriginalMobileFramebufferABI.h'):
    data=subprocess.check_output(['git','-C',str(ROOT/'drivers/GopFramebuffer'),'show',revision+':'+name],timeout=30)
    require(hashlib.sha256(data).hexdigest()==build['source_sha256']['drivers/GopFramebuffer/'+name],
            'Exact committed driver implementation')
for name,digest in build['source_sha256'].items():require(sha(ROOT/name)==digest,'Actual provider/instrument source unchanged')
require(sha(OUT/'NativeMobileDisplay.o')==build['compiled_object_sha256'] and sha(OUT/'NativeMobileDisplay.late.o')==build['late_object_sha256'],
        'Exact actual own objects')
candidate=ROOT/'build/xnu-prelink/native-owner-mobile-provider-query-candidate.macho'
plan=json.loads(candidate.with_suffix('.json').read_text());raw=candidate.read_bytes();parsed=macho(raw)
require(sha(candidate)==plan['candidate_sha256'],'Exact observed original-component candidate')
names={name:va for va,ns in exports(raw,parsed).items() for name in ns}
# Inline weak methods can become local definitions in the real kernel link.
# Read their actual nlist entries rather than inferring an address from a vtable.
native_st=next(p for cmd,p,_ in parsed['commands'] if cmd==2)
native_sy,native_count,native_strings,_=struct.unpack_from('<4I',raw,native_st+8)
for i in range(native_count):
    ix,kind,section,_,va=struct.unpack_from('<IBBHQ',raw,native_sy+i*16)
    if not kind&0xe0 and kind&0xe==0xe and section:
        name=raw[native_strings+ix:raw.index(b'\0',native_strings+ix)].decode()
        if not name.startswith(('__ZN19NativeMobileDisplay','__ZNK19NativeMobileDisplay')):
            continue
        require(name not in names or names[name]==va,'Unambiguous actual linked symbol')
        names[name]=va
def field(d,name,size=4):
    key=f'{names[name]:x}:{size:x}'
    require(key in d['memory'] and not d['memory'][key].startswith('E'),'Actual readable kernel field '+name)
    return int.from_bytes(bytes.fromhex(d['memory'][key]),'little')
original=json.loads((ROOT/'build/xnu-prelink/native-owner-mobile-graphics-candidate.json').read_text())
family='com.apple.iokit.IOMobileGraphicsFamily'
extent=next(e for e in plan['extents'] if e['module']==family and e['segment']=='__TEXT_EXEC')
at=backed_offset(parsed['segments'],extent['va'],extent['size'],len(raw))
require(hashlib.sha256(raw[at:at+extent['size']]).hexdigest()==plan['original_executable_sha256'][family]
        ==original['original_executable_sha256'][family],'Actual complete original family code unchanged')
# Verify the source-compiled behavior in the observed candidate, masking only
# own object relocation words that the real linker is required to resolve.
obj=(OUT/'NativeMobileDisplay.o').read_bytes();oi=macho(obj)
st=next(p for cmd,p,_ in oi['commands'] if cmd==2)
sy,count,strings,_=struct.unpack_from('<4I',obj,st+8);symbols=[]
for i in range(count):
    ix,kind,section,_,va=struct.unpack_from('<IBBHQ',obj,sy+i*16)
    symbols.append((obj[strings+ix:obj.index(b'\0',strings+ix)].decode(),kind,section,va))
sections=[s for g in oi['segments'] for s in g['sections']]
code_checks=[]
for part in ('beforeExternalMethod','releaseClientState','getDisplayDimensions'):
    symbol,_,section,start=next(s for s in symbols if part in s[0] and s[1]&0xe==0xe)
    sec=sections[section-1]
    end=min([s[3] for s in symbols if s[2]==section and s[3]>start]+[sec['va']+sec['size']])
    size=end-start;source=bytearray(obj[sec['fileoff']+start-sec['va']:sec['fileoff']+end-sec['va']])
    target=names[symbol];at=backed_offset(parsed['segments'],target,size,len(raw));linked=bytearray(raw[at:at+size])
    ro,rc=struct.unpack_from('<II',obj,sec['command_offset']+56);masked=[]
    for i in range(rc):
        offset,bits=struct.unpack_from('<II',obj,ro+i*8);position=sec['va']+offset-start
        if 0<=position<size:
            require(position%4==0 and position+4<=size,'Aligned actual instruction relocation')
            source[position:position+4]=linked[position:position+4]=bytes(4);masked.append(position)
    require(source==linked and size>len(set(masked))*4,'Actual linked own method instructions '+part)
    code_checks.append(dict(method=part,bytes=size,relocated_words=sorted(set(masked)),masked_sha256=hashlib.sha256(source).hexdigest()))
observations={}
for case in ('query','headless','default-off'):
    path=ROOT/f'build/darwinboot-owner-hvf-mobile-provider-{case}/gdb-stop.json';d=json.loads(path.read_text())
    require(d['kernel_sha256']==plan['candidate_sha256'] and not d['bounded_timeout_interrupted'] and d['qemu_accelerator']=='hvf','Actual bounded same-candidate boot')
    r={k:int(v,16) for k,v in d['system_registers'].items()}
    require(d['native_4k_mmu_observed'] and (r['TCR_EL1']>>14)&3==0 and (r['TCR_EL1']>>30)&3==2
            and r['SCTLR_EL1']&1 and r['TTBR0_EL1'] and r['TTBR1_EL1'],'Actual active native-4K CPU translations')
    v=d['actual_boot_video']['pe_video']
    stage=field(d,'_native_mobile_provider_stage');meta=field(d,'_native_mobile_provider_meta_status')
    if case=='query':
        require(d['stop_symbol']=='_native_mobile_display_provider_checkpoint' and stage==5 and meta==0
                and field(d,'_native_mobile_provider_query_status')==0 and field(d,'_native_mobile_provider_parent_match')==1
                and field(d,'_native_mobile_provider_released')==1,'Real original client start/query/stop/release and typed parent relationship')
        dimensions=field(d,'_native_mobile_provider_dimensions',16)
        require(dimensions==field(d,'_native_mobile_provider_expected',16)==v['v_width']|(v['v_height']<<64)
                and v['v_width']==800 and v['v_height']==600 and v['v_depth']==32 and v['v_rowBytes']==3200,
                'Actual original selector output matches actual GOP/PE video')
    elif case=='headless':
        require(d['stop_symbol']=='_native_mobile_display_provider_checkpoint' and stage==2 and meta==0
                and not field(d,'_native_mobile_provider_object',8) and not field(d,'_native_mobile_provider_client',8)
                and field(d,'_native_mobile_provider_query_status')==0xffffffff and not any(v.values()),
                'Actual no-video backend creation refusal, without invented display geometry')
    else:
        require(not stage and meta==0xffffffff and d['original_launchd_main_executed']
                and d['followed_main_entry']['first_instruction_completed'] and d['original_amfi_table_owner_observed']
                and d['owner_root_binding_audit']['boot_root_accepted']
                and d['owner_root_binding_audit']['_native_owner_root_apple_autherr']==80
                and set(d['direct_user_commpage_shifts'].values())=={12}
                and d['actual_signature_failures']==dict(_cs_validate_page_bad_hash=0,_cs_validate_page_no_hash=0),
                'Disabled provider path preserves genuine original launchd, AMFI/root and native user page ABI')
    observations[case]=dict(checkpoint_sha256=sha(path),stage=stage,actual_tcr=r['TCR_EL1'])
(OUT/'native-checkpoint.json').write_text(json.dumps(dict(candidate_sha256=plan['candidate_sha256'],
    kit_revision=revision,
    source_sha256=build['source_sha256'],implemented_entries=[182,193,249],actual_original_client_selector=8,
    actual_original_client_start_query_stop_release=True,actual_dimensions=[800,600],headless_refused=True,
    linked_method_checks=code_checks,observations=observations,native_cpu_page_bytes=4096,
    unclassified_extension_entries=91,display_published=False,presentation=False,gpu_execution=False,
    active_gpu_smmu_qualified=False,metal_device=False,original_desktop=False),indent=2)+'\n')
print('PASS: real original framebuffer client queries actual 800x600 provider, then stops/releases; headless refuses')
print('Default-off original launchd/AMFI/root/user-4K preserved; display publication and presentation remain incomplete')
