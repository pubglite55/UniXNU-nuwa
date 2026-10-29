#!/usr/bin/env python3
"""Qualify the real descriptor-provision boundary of the original IOGPU provider.

The opt-in instrument supplies one real owned IOBufferMemoryDescriptor at the
original slot-170 hook. The provider object is still deliberately unattached
and unregistered, so the original client factory stops with its genuine
kIOReturnInternalError. No device, mapping, queue, GPU submission, Metal
device or desktop is claimed.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'build/darwinboot-owner-hvf-original-descriptor-provision-0x1/gdb-stop.json'
CHECKPOINT = ROOT / 'build/native-original-provider/descriptor-provision-checkpoint.json'

report = json.loads(REPORT.read_text())
provider = report.get('native_original_provider')
if not provider:
    raise SystemExit('Missing original provider observation')
if provider.get('descriptor_provisioned') != 1:
    raise SystemExit('No real descriptor was provisioned')
if provider.get('descriptor_refused') != 0:
    raise SystemExit('Descriptor provision must not take the refusal path')
if provider.get('callback') != 170:
    raise SystemExit(f"Expected slot-170 observation, got {provider.get('callback')!r}")
if provider.get('attached') != 0 or provider.get('registered') != 0:
    raise SystemExit('This checkpoint requires the deliberately unattached provider')
if provider.get('factory_result') != -536870199:
    raise SystemExit(f"Expected genuine kIOReturnInternalError, got {provider.get('factory_result')!r}")
if provider.get('client_instances_live') != 0:
    raise SystemExit('No client instance may survive this boundary')
if not report.get('native_4k_mmu_observed'):
    raise SystemExit('Native 4K must be active')
result = {
    'kernel_sha256': report['kernel_sha256'],
    'descriptor_provisioned': True,
    'descriptor_hook': 170,
    'provider_allocated': bool(provider.get('allocated')),
    'provider_initialized': bool(provider.get('initialized')),
    'provider_attached': False,
    'provider_registered': False,
    'client_factory_result': provider['factory_result'],
    'client_factory_result_name': 'kIOReturnInternalError',
    'client_instances_live': 0,
    'mapping_or_device_supplied': False,
    'gpu_submission': False,
    'system_metal_device': False,
    'native_4k_observed': True,
    'qemu_only': True,
    'sheng_hardware_tested': False,
}
CHECKPOINT.parent.mkdir(parents=True, exist_ok=True)
CHECKPOINT.write_text(json.dumps(result, indent=2) + '\n')
print('PASS: real descriptor reaches original slot 170')
print('PASS: genuine factory internal error from the unattached provider')
print('Open: provider attach/register, slot 189 device, mapping/queue, GPU execution')
