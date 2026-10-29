#!/usr/bin/env python3
"""Qualify the attach-only original IOGPU factory boundary.

Mode 7 attaches the original provider but deliberately skips registerService,
then supplies a real descriptor at slot 170. The factory still returns its
genuine kIOReturnInternalError, proving attachment alone is insufficient and
the registration path (required slot 84) is part of the client contract.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'build/darwinboot-owner-hvf-original-descriptor-provision-attached-only-0x1/gdb-stop.json'
CHECKPOINT = ROOT / 'build/native-original-provider/attach-only-checkpoint.json'

report = json.loads(REPORT.read_text())
provider = report.get('native_original_provider')
if not provider:
    raise SystemExit('Missing original provider observation')
if provider.get('callback') != 170:
    raise SystemExit(f"Expected descriptor slot 170, got {provider.get('callback')!r}")
if provider.get('descriptor_provisioned') != 1:
    raise SystemExit('The real descriptor was not provisioned')
if provider.get('attached') != 1 or provider.get('registered') != 0:
    raise SystemExit('This checkpoint requires attached-only state')
if provider.get('factory_result') != -536870199:
    raise SystemExit(f"Expected genuine kIOReturnInternalError, got {provider.get('factory_result')!r}")
if provider.get('client_instances_live') != 0:
    raise SystemExit('No client instance may survive')
if not report.get('native_4k_mmu_observed'):
    raise SystemExit('Native 4K must be active')
result = {
    'kernel_sha256': report['kernel_sha256'],
    'provider_attached': True,
    'provider_registered': False,
    'descriptor_provisioned': True,
    'descriptor_hook': 170,
    'client_factory_result': provider['factory_result'],
    'client_factory_result_name': 'kIOReturnInternalError',
    'client_instances_live': 0,
    'registration_required_before_factory': True,
    'device_or_mapping_supplied': False,
    'gpu_submission': False,
    'system_metal_device': False,
    'native_4k_observed': True,
    'qemu_only': True,
    'sheng_hardware_tested': False,
}
CHECKPOINT.parent.mkdir(parents=True, exist_ok=True)
CHECKPOINT.write_text(json.dumps(result, indent=2) + '\n')
print('PASS: attach-only provider reaches slot 170 with a real descriptor')
print('PASS: factory still returns genuine internal error without registration')
print('Open: genuine registration/slot-84 semantics, slot 189 device/resource/queue, GPU execution')
