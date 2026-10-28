#!/bin/bash
# Full 4 KiB XNU build for nuwa (Xiaomi 13 Pro, SM8550) on macOS.
# Run from the UniXNU-nuwa checkout:  bash build-on-mac.sh <mode>
#   mode = check  : only report the environment
#   mode = fetch  : clone the six components + corecrypto source
#   mode = build  : build corecrypto archives then the kernel
set -euo pipefail

MODE=${1:-check}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"

check_env() {
  echo '=== host ==='
  sw_vers
  xcodebuild -version 2>/dev/null || { echo 'Xcode not selected: sudo xcode-select -s /Applications/Xcode.app'; return 1; }
  echo "sdk: $(xcrun --sdk macosx --show-sdk-path)"
  echo "arch: $(uname -m)  cpus: $(sysctl -n hw.ncpu)"
  local missing=0
  for t in brew cmake ninja unifdef git python3; do
    if command -v "$t" >/dev/null 2>&1; then printf '  %-10s ok\n' "$t"; else printf '  %-10s MISSING\n' "$t"; missing=1; fi
  done
  if [ $missing -ne 0 ]; then echo 'install with: brew install cmake ninja unifdef'; return 1; fi
}

fetch_components() {
  clone() { [ -d "$1/.git" ] || git clone --depth 1 "$2" "$1"; }
  clone drivers/ArmDTPlatform https://github.com/UniXNU/ArmDTPlatform.git
  clone drivers/ArmCpu        https://github.com/UniXNU/ArmCpu.git
  clone drivers/DarwinBoot    https://github.com/UniXNU/DarwinBoot.git
  clone drivers/SoftwareAES   https://github.com/UniXNU/SoftwareAES.git
  clone kits/XnuPrelink       https://github.com/UniXNU/XnuPrelink.git
  clone kits/ArmSmmu4K        https://github.com/UniXNU/ArmSmmu4K.git
  if [ ! -d refer/corecrypto-2023/.git ]; then
    git clone https://github.com/ONLYA/corecrypto-2023.git refer/corecrypto-2023
  fi
  git -C refer/corecrypto-2023 checkout -q 11fba65b12d8830630e248dfa8344caf8b065f26
  echo 'components ready'
}

build_crypto() {
  python3 scripts/build-corecrypto-14.py
  python3 scripts/build-corecrypto-14.py --namespace
  ls -l build/corecrypto-2023/libcorecrypto_kernel_noasm*.a
}

build_kernel() {
  export XNU_ARM_DT_PLATFORM=1 XNU_ARMCPU=1 XNU_NATIVE_UFS=1 XNU_NATIVE_AES=1
  export XNU_SOURCE_CORECRYPTO14=1 XNU_SOURCE_PTHREAD=1 XNU_SHENG_PMGR=1
  export XNU_NATIVE_ARCH_TIMER=1 XNU_NATIVE_PAN=1 XNU_DT_PANIC_REGION=1
  export XNU_CRYPTO_BOOTSTRAP=prelinked
  export XNU_TRUST_CACHE_RUNTIME=0 XNU_VERIFIED_ROOT_PROBE=0 XNU_BOOT_PROGRESS=0
  export XNU_NATIVE_MOBILE_DISPLAY=0 XNU_ARMVIRT_PLATFORM=0
  export JOBS=$(sysctl -n hw.ncpu)
  bash -x scripts/build-xnu-4k-baseline.sh 2>&1 | tee "$ROOT/xnu-4k-build.log"
}

case "$MODE" in
  check) check_env ;;
  fetch) check_env && fetch_components ;;
  build) check_env && fetch_components && build_crypto && build_kernel ;;
  *) echo "usage: $0 {check|fetch|build}"; exit 2 ;;
esac

echo
echo '=== result ==='
ls -l build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf 2>/dev/null || echo 'kernel not produced yet'