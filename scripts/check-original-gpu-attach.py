#!/usr/bin/env python3
"""Qualify the original IOGPU provider attach boundary.

Mode 6 attaches and registers the original provider. Attachment succeeds, but
the original registerService immediately reaches its required slot-84
registration-save hook, which this instrument never fakes; the probe stops
there. No client factory, descriptor, device, mapping, queue, GPU execution or
Metal device is reached.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'build/darwinboot-owner-hvf-original-descriptor-provision-attached-0x1/gdb-stop.json'
CHECKPOINT = ROOT / 'build/native-original-provider/attach-checkpoint.json'

report = json.loads(REPORT.read_text())
provider = report.get('native_original_provider')
if not provider:
    raise SystemExit('Missing original provider observation')
if provider.get('callback') != 84:
    raise SystemExit(f"Expected required slot-84 registration hook, got {provider.get('callback')!r}")
if provider.get('attached') != 1:
    raise SystemExit('The provider attachment did not succeed')
if provider.get('registered') != 0:
    raise SystemExit('Registration must not have completed through the fake path')
if provider.get('descriptor_provisioned') != 0 or provider.get('descriptor_refused') != 0:
    raise SystemExit('The client factory must not reach the descriptor hook in this boundary')
if provider.get('client_instances_live') != 0:
    raise SystemExit('No client instance may survive')
if not report.get('native_4k_mmu_observed'):
    raise SystemExit('Native 4K must be active')
result = {
    'kernel_sha256': report['kernel_sha256'],
    'provider_attached': True,
    'provider_registered': False,
    'registration_required_hook': 84,
    'client_factory_reached': False,
    'descriptor_provisioned': False,
    'client_instances_live': 0,
    'device_or_mapping_supplied': False,
    'gpu_submission': False,
    'system_metal_device': False,
    'native_4k_observed': True,
    'qemu_only': True,
    'sheng_hardware_tested': False,
}
CHECKPOINT.parent.mkdir(parents=True, exist_ok=True)
CHECKPOINT.write_text(json.dumps(result, indent=2) + '\n')
print('PASS: real original provider attachment succeeds')
print('PASS: genuine registration-save slot 84 is reached and not faked')
print('Open: slot-84 semantics, attach-only factory, device/resource/queue, GPU execution')
