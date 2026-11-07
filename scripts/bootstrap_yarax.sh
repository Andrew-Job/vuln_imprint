#!/usr/bin/env bash
# Build the pinned upstream YARA-X C API; CI may defer the first-party scanner build.
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
git submodule update --init --recursive
rustup toolchain install 1.99.1 --profile minimal
cargo +1.99.1 install cargo-c --version 0.10.26 --locked
export CARGO_TARGET_DIR="$ROOT/external/yara-x/target"
(
    cd external/yara-x
    cargo +1.99.1 cinstall -p yara-x-capi --profile release-lto --library-type staticlib \
        --locked --prefix "$YARAX_PREFIX" \
        --libdir "$YARAX_PREFIX/lib"
)
export PKG_CONFIG_PATH="$YARAX_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
if [[ "$BUILD_SCANNER" == "1" ]]; then
    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel 2
    python3 scripts/native_yarax_smoke.py --scanner build/scanner/vulnimprint-scan
fi
