#!/usr/bin/env python3
"""Derive original client factory, mapping and provider/device dependencies."""
import hashlib,json,runpy,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
provider=runpy.run_path(str(ROOT/'scripts/audit-target-iogpu-start-contract.py'))
client=runpy.run_path(str(ROOT/'scripts/audit-target-iogpu-userclient.py'))
n=provider['n'];read,require=n['read'],n['require'];values=provider['abi']['inherited_entries'];uc=client['values']
def words(address,size):return struct.unpack('<'+'I'*(size//4),read(address,size))
def entry(address,size):return dict(address=hex(address),bytes=size,sha256=hashlib.sha256(read(address,size)).hexdigest())
new_client=values[141];factory=words(new_client,372)
require(factory[10:17]==(0xaa0403f4,0xaa0303f7,0xf900009f,0x52800028,0xb9017e68,0x12003c68,0x7100851f),'Actual output x4 cleared, saved open type x3 and low16 type selector')
require(factory[18]==0x7100051f and factory[20:24]==(0xaa0103f6,0xf9400268,0xf9431d08,0xaa1303e0),'Actual type1 factory dispatches original slot199 with real this')
require(factory[26:35]==(0xaa0003f5,0x53107ef7,0xf9400008,0xf9401108,0xd63f0100,0xaa1503e0,0xd2800001,0xaa1603e2,0xaa1703e3),'Actual high16 open type passed as scalar x3, real owning task x2 and NULL properties x1')
initialize=n['branch'](new_client+35*4);init=words(initialize,148)
require(init[4:7]==(0xaa0303f5,0xaa0203f4,0xaa0003f3) and init[23:25]==(0xf9000114,0xf9009675),'Actual custom initializer saves task and scalar subtype, not an output-pointer argument')
require(factory[55:61]==(0xf94002a8,0xf941b108,0xaa1503e0,0xaa1303e1,0xd63f0100,0x340002c0) and factory[61:69]==(0xf94002a8,0xf9415908,0xaa1503e0,0xaa1303e1,0xd63f0100,0x34000160,0x52800000,0xf9000295),'Actual original start must succeed before output object is published to caller')
require(factory[6:9]==(0x528057d8,0x72bc0018,0x11001300) and factory[77:88]==(0xf94002a8,0xf941b508,0xaa1503e0,0xaa1303e1,0xd63f0100,0x11002f18,0xf94002a8,0xf9401508,0xaa1503e0,0xd63f0100,0xaa1803e0),'Actual failed original start detaches/releases client and returns original 0xe00002c9')

initialize_device=uc[186];body=words(initialize_device,436)
require(body[6:12]==(0xf9407c00,0x91046261,0xf9400008,0xf942a908,0xd63f0100,0xf9008660),'First required slot170 gets client+280 output and returns actual descriptor stored at+264')
require(body[13:16]==(0xf9400008,0xf9401108,0xd63f0100),'Actual returned shared descriptor is retained')
require(body[16:24]==(0xf9408660,0xf9406e68,0xf9400101,0xd2800002,0x52820023,0x72a08003,0xd2800004,0xd2800005),'Actual owner task and native createMappingInTask options 0x04001001 with zero address/offset/length')
mapping=n['imported'](n['branch'](initialize_device+24*4))
require(mapping==n['names']['__ZN18IOMemoryDescriptor19createMappingInTaskEP4taskyjyy'],'Actual native IOMemoryDescriptor mapping import')
require(body[25:35]==(0xf9008a60,0xb4000660,0xf9407e60,0xf9406e68,0xf9400101,0xf9409662,0xf9400008,0xf942c508,0xd63f0100,0xf9009260),'Mapping stored+272; slot189 receives real owning task and loaded subtype scalar; device stored+288')
require(body[12]==0xb40006a0 and body[76]==0x14000018 and body[100:104]==(0xaa1303e0,0x9400000b,0x52800014,0xaa1403e0) and n['branch'](initialize_device+404)==uc[187],'Actual NULL descriptor follows original error/cleanup path and returns false')
first=provider['values'][170];first_words=struct.unpack('<3I',provider['original_read'](first,12))
require(first_words==(0xb900003f,0xf9421800,0xd65f03c0),'Actual concrete slot170 writes uint32 output and returns descriptor from own+1072')
second=provider['values'][189];second_words=struct.unpack('<36I',provider['original_read'](second,144))
require(second_words[4:10]==(0xaa0103f4,0xaa0003f5,0xf9400008,0xf9440508,0xd63f0100,0xb40002e0),'Actual concrete slot189 allocates via own slot257, not an invented device')
require(second_words[10:18]==(0xaa0003f3,0xf9400008,0xf9405508,0xaa1503e1,0xaa1403e2,0xd2800003,0xd63f0100,0x34000220),'Actual concrete device slot21 receives original provider/task/zero; failed init refuses')
# Pin the exact original cleanup, including guarded release of actual mapping
# and descriptor. A missing backend may refuse; an empty buffer is not a device.
cleanup=uc[187];clean=words(cleanup,112)
require(clean[12:25]==(0xf9408a60,0xb4000080,0xf9400008,0xf9401508,0xd63f0100,0xf9008a7f,0xf9408660,0xb4000080,0xf9400008,0xf9401508,0xd63f0100,0xf900867f,0x3904027f),'Actual cleanup guards/releases mapping+272 and descriptor+264, then clears active flag')
report=dict(original_kernel_sha256=provider['n']['plan']['original_sha256'],original_iogpu_text_sha256=provider['n']['plan']['original_executable_sha256']['com.apple.iokit.IOGPUFamily'],
 new_user_client=entry(new_client,372),custom_client_initialize=entry(initialize,148),initialize_device=entry(initialize_device,436),cleanup=entry(cleanup,112),
 device_factory_open_type_low16=1,device_factory_open_subtype_shift=16,client_subtype_offset=296,shared_descriptor_slot=170,shared_descriptor_out_offset=280,shared_descriptor_offset=264,
 mapping_import='__ZN18IOMemoryDescriptor19createMappingInTaskEP4taskyjyy',mapping_options=0x04001001,mapping_offset=272,device_factory_slot=189,device_offset=288,
 first_required_callback_caller_lr=hex(initialize_device+44),absent_descriptor_factory_error=0xe00002c9-(1<<32),concrete_shared_descriptor_field=1072,concrete_device_allocator_slot=257,concrete_device_initializer_slot=21,
 source_analysis_only=True,source_signatures_complete=False,original_client_started=False,backend_resources_implemented=False,normal_device_discovery=False,original_desktop=False,adreno_execution=False)
(ROOT/'build/gpu-analysis/original-iogpu-client-contract.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: original type1 factory/custom task+subtype initialization, shared descriptor/map, required device object and guarded cleanup derived')
print('No successful client start or empty-buffer/device substitute is qualified')
