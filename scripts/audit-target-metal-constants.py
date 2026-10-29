#!/usr/bin/env python3
"""Read exact original constant accessors without copying executable components."""
import runpy,json
n=runpy.run_path(__file__.replace('audit-target-metal-constants.py','audit-target-metal-device.py'))
cls,pointer,require=n['cls'],n['pointer'],n['require']
# These original cache class references are derived from the original factory
# and newIndexed/NamedConstantArray call sites; UUID-bound read-only metadata.
values=cls(0x1f489d8b8);indexed=cls(pointer(0x1e6481a88));named=cls(pointer(0x1e6481a80))
require(n['main'][88:104].hex()=='590d839a82d230f1a17d0cc053420f73','Exact target cache UUID')
require(values['name']=='MTLFunctionConstantValuesInternal' and values['instance_size']==16 and
    cls(values['superclass'])['name']=='MTLFunctionConstantValues','Actual constant values class and ancestry')
for c,identity in ((indexed,'index'),(named,'name')):
    require(c['name']==('MTLIndexedConstantValue' if identity=='index' else 'MTLNamedConstantValue') and c['instance_size']==32,'Original descriptor class')
    methods={m['selector']:m for m in c['methods']}
    for selector,encoding in {'data':'^v16@0:8','dataType':'Q16@0:8',identity:'Q16@0:8' if identity=='index' else '@16@0:8'}.items():
        require(methods[selector]['encoding']==encoding,'Exact typed original accessor: '+selector)
methods={m['selector']:m for m in values['methods']}
require(all(methods[s]['encoding']=='@16@0:8' for s in ('newIndexedConstantArray','newNamedConstantArray')),'Actual original array accessor ABI')
(n['OUT']/'metal-constant-accessor-abi.json').write_text(json.dumps(dict(cache_uuid=n['main'][88:104].hex(),values=values,indexed=indexed,named=named,
    metadata_only=True,original_methods_unchanged=True),indent=2)+'\n')
print('PASS: exact original constant arrays and typed data/type/index/name getters; original implementations preserved')
