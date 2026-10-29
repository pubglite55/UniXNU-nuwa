#!/usr/bin/env python3
"""Qualify real original compressed-file handling after owner root enforcement."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/XnuPrelink'))
import native_prelink as np
from emit_prelink import ADLER32_VECTOR_DIGEST, VECTOR_REPEAT_DIGEST, pc_relative_target


def require(value, message):
    if not value:
        raise SystemExit(message)


def report(name):
    return json.loads((ROOT / ('build/darwinboot-owner-root-' + name) / 'gdb-stop.json').read_text())


permissions, refusal, positive = (report(name) for name in ('vnode-authorize', 'decmpfs-refusal', 'fscompression-cache-paths'))
for d, symbol, value in ((permissions, '_vnode_authorize', 0), (refusal, '_decmpfs_read_compressed', 45)):
    require(d['kernel_sha256'] == 'bd231941e1ff79c2f1917f99c2e5f05720d5f0a1fdc3d325f732609cb9ecfd63' and
            not d['bounded_timeout_interrupted'] and d['stop_symbol'] == symbol and
            d['function_return_stack_matched'] and int(d['x0'], 16) == value,
            'Require real permission success and actual unsupported compressed-file return')
require(int(permissions['function_entry_arguments'][2], 16) == 8, 'Observe the actual executable permission request')

candidate = ROOT / 'build/xnu-prelink/native-owner-root-fscompression-candidate'
plan = json.loads(candidate.with_suffix('.json').read_text())
kernel = candidate.with_suffix('.macho').read_bytes()
require(positive['kernel_sha256'] == plan['candidate_sha256'] == hashlib.sha256(kernel).hexdigest() ==
        '89bcaaefbc6ef4ff2c45614a4b983b723792b8b6adefc3fbc58c6bd7e4b808c9' and
        plan['native_sha256'] == '9b9844ffcd9be5d8dc6f1da2a6e7200cb10e58672091579583277111765a6151' and
        len(plan['components']) == 15 and not positive['bounded_timeout_interrupted'], 'Require exact bounded 15-component candidate')
original = (ROOT / '.cache/firmware/kernelcache.macho/kernelcache.release.ipad7.decompressed').read_bytes()
require(hashlib.sha256(original).hexdigest() == 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7',
        'Require supplied ordinary-ARM64 original')
meta, old = np.macho(kernel), np.macho(original)
component = 'com.apple.AppleFSCompression.AppleFSCompressionTypeZlib'
for extent in plan['extents']:
    if extent['segment'] != '__TEXT_EXEC':
        continue
    at = np.backed_offset(meta['segments'], extent['va'], extent['size'], len(kernel))
    prev = np.backed_offset(old['segments'], extent['va'] - plan['slide'], extent['size'], len(original))
    require(kernel[at:at + extent['size']] == original[prev:prev + extent['size']], 'Every original executable extent must remain unchanged')
repeat = bytes(i % d if d else 0 for d in range(16) for i in range(32))
repeat += bytes(32 if d < 3 else 16 if d in (4, 8) else (32 // d) * d for d in range(16))
adler = bytes(range(32, 0, -1)) + struct.pack('<II', 65521, ((1 << 47) + 65520) // 65521)
for data, digest in ((repeat, VECTOR_REPEAT_DIGEST), (adler, ADLER32_VECTOR_DIGEST)):
    require(hashlib.sha256(data).hexdigest() == digest, 'Regenerate exact mathematical constants, not arbitrary instruction exceptions')
    literal = next(v for v in plan['known_inline_data'] if v['module'] == component and v['sha256'] == digest)
    at = np.backed_offset(old['segments'], literal['va'], literal['size'], len(original))
    require(original[at:at + literal['size']] == data, 'Actual original pool must match every mathematical constant byte')
for pc, target in ((0xfffffff006b20f18, 0xfffffff006b21100), (0xfffffff006b20f1c, 0xfffffff006b21300)):
    at = np.backed_offset(old['segments'], pc, 4, len(original))
    word = struct.unpack_from('<I', original, at)[0]
    require(word & 0x9f000000 == 0x10000000 and pc_relative_target(word, pc) == (target, False), 'Actual original ADR references must address the literal pools')
for kind, registration in positive['compression_registrations'].items():
    pointer, data = int(registration['pointer'], 16), bytes.fromhex(registration['bytes'])
    require(kind in ('3', '4') and struct.unpack_from('<I', data)[0] == 3 and any(
        e['module'] == component and e['segment'] == '__DATA_CONST' and e['va'] <= pointer < e['va'] + e['size']
        for e in plan['extents']), 'Real type-3/type-4 registrations must belong to the original component')
    at = np.backed_offset(meta['segments'], pointer, len(data), len(kernel))
    require(kernel[at:at + len(data)] == data, 'Actual registration fields must match the rebased original table')
    fetch = struct.unpack_from('<Q', data, 24)[0]
    require(any(e['module'] == component and e['segment'] == '__TEXT_EXEC' and e['va'] <= fetch < e['va'] + e['size']
                for e in plan['extents']), 'Actual fetch callback must execute original component code')
    t = registration['translation']
    require(t['leaf_level'] == 2 and t['leaf_bytes'] == 2097152 and t['ap'] == 2 and t['pxn'] and t['uxn'],
            'Actual original registrations must be RO/NX blocks within native 4K-granule tables')
regs = {k: int(v, 16) for k, v in positive['system_registers'].items()}
require(regs['TCR_EL1'] >> 14 & 3 == 0 and regs['TCR_EL1'] >> 30 & 3 == 2 and regs['SCTLR_EL1'] & 1 and
        regs['TTBR0_EL1'] and regs['TTBR1_EL1'], 'Require active native 4K hardware translation')
require(positive['original_amfi_table_owner_observed'] and positive['original_crypto_table_owner_observed'] and
        positive['original_crypto_initialized_observed'] and positive['owner_root_binding_audit']['boot_root_accepted'] and
        positive['owner_root_binding_audit']['_native_owner_root_apple_autherr'] == 80, 'Root must still use genuine owner enforcement and original AMFI/crypto')
io, integrity = positive['native_virtio_globals'], positive['native_virtio_integrity']
require(io['_native_virtio_read_requests'] == 226 and io['_native_virtio_read_failures'] == 0 and
        integrity['_native_virtio_verified_blocks'] == 526 and integrity['_native_virtio_integrity_failures'] == 0,
        'Original compressed-file execution must consume only actual authenticated I/O')
require(any(e['symbol'] == component + ':kmod_start' for e in positive['trace_events']) and
        any(e['symbol'] == '_exec_mach_imgact' for e in positive['trace_events']), 'Observe real original module start and Mach-O activation')
fatal = positive['fatal_user_exit']
require(positive['stop_symbol'] == '_panic_with_options' and fatal['namespace'] == 6 and fatal['code'] == 1 and
        '/usr/lib/libSystem.B.dylib' in fatal['description'] and '/sbin/launchd' in fatal['description'] and
        'no dyld cache' in fatal['description'] and any(e['number'] == 5 and e.get('path') ==
        '/System/Library/Caches/com.apple.dyld/' for e in positive['syscall_events']), 'Preserve genuine later dyld missing-cache exit and actual default directory request')
print('PASS: real permissions succeed; absent decompressor returns ENOTSUP; original component supplies actual type-4 callback')
print('PASS: 15 original executable extents remain unchanged; authenticated native4K root reaches genuine dyld missing-cache exit')
print('No launchd main, complete shared-cache loading, production secure boot or hardware boot is claimed')
