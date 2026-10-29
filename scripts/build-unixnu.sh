#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [ "$(uname -s)" = Darwin ]; then
  LLVM_PREFIX=${LLVM_PREFIX:-$(brew --prefix llvm)}
  LLD_PREFIX=${LLD_PREFIX:-$(brew --prefix lld)}
  TOOLS=$ROOT/.cache/toolchain
  mkdir -p "$TOOLS"
  for tool in clang llvm-lib llvm-rc; do
    ln -sf "$LLVM_PREFIX/bin/$tool" "$TOOLS/$tool"
  done
  ln -sf "$LLD_PREFIX/bin/lld-link" "$TOOLS/lld-link"
  export CLANG_BIN=$TOOLS/
fi
export JOBS=${JOBS:-4}
exec "$ROOT/package/build.sh" "$@"
