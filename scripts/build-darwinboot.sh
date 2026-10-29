#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export WORKSPACE=$ROOT
EDK2=${UNIXNU_EDK2:-$ROOT/refer/edk2}
if [ ! -f "$EDK2/MdePkg/MdePkg.dec" ]; then
  EDK2=${UNIXNU_EDK2:-$ROOT/package/Mu_Basecore}
fi
export PACKAGES_PATH=$ROOT/drivers/DarwinBoot:$ROOT/package:$EDK2
export EDK_TOOLS_PATH=$EDK2/BaseTools
export CONF_PATH=${CONF_PATH:-$ROOT/../package/Build/Conf}
if [ ! -d "$CONF_PATH" ]; then
  export CONF_PATH=$ROOT/package/Build/Conf
fi
export CLANG_BIN=${CLANG_BIN:-$ROOT/../toolchain/}
if [ ! -x "$CLANG_BIN/clang" ]; then
  export CLANG_BIN=$ROOT/.cache/toolchain/
fi
export PYTHON_COMMAND=python3
export PATH=$EDK_TOOLS_PATH/BinWrappers/PosixLike:$EDK_TOOLS_PATH/Source/C/bin:$PATH
cd "$ROOT"
build -p DarwinBootPkg/DarwinBoot.dsc -a AARCH64 -b "${TARGET:-DEBUG}" -t CLANGPDB -n "${JOBS:-4}"
