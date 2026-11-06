#!/usr/bin/env bash
# Build the pinned YARA-X C API and optionally the first-party Scanner.
# Rust, cargo-c and Git submodules are provisioned by the caller.
set -euo pipefail
BUILD_SCANNER=1
if [[ $# -gt 0 ]]; then
    if [[ $# -eq 1 && "$1" == "--capi-only" ]]; then
        BUILD_SCANNER=0
    else
        echo "Usage: $0 [--capi-only]" >&2
        exit 2
    fi
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
: "${YARAX_PREFIX:=$HOME/.local}"
python3 scripts/verify_dependencies.py --require-checkout
export CARGO_TARGET_DIR="$ROOT/external/yara-x/target"
(
    cd external/yara-x
    cargo +1.99.1 cinstall -p yara-x-capi --profile release-lto --library-type staticlib \
        --locked --prefix "$YARAX_PREFIX" \
        --libdir "$YARAX_PREFIX/lib"
)
export PKG_CONFIG_PATH="$YARAX_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
test -s "$YARAX_PREFIX/lib/libyara_x_capi.a" || { echo "YARA-X static library missing" >&2; exit 2; }
version="$(pkg-config --modversion yara_x_capi)"
test "$version" = '1.23.0' || { echo "Wrong YARA-X C API version: $version" >&2; exit 2; }
if [[ "$BUILD_SCANNER" == "1" ]]; then
    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel 2
    python3 scripts/native_yarax_smoke.py --scanner build/scanner/vulnimprint-scan
fi
