#!/usr/bin/env bash
# Build only the pinned upstream YARA-X Git submodule; no substitute matcher.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
: "${YARAX_PREFIX:=$HOME/.local}"
git submodule update --init --recursive
python3 scripts/verify_dependencies.py --require-checkout
test -f external/yara-x/Cargo.lock || { echo 'Pinned Cargo.lock missing' >&2; exit 2; }
rustup toolchain install 1.99.1 --profile minimal
cargo +1.99.1 install cargo-c --version 0.10.26 --locked
(
    cd external/yara-x
    cargo +1.99.1 cinstall -p yara-x-capi --release --locked --prefix "$YARAX_PREFIX" \
        --libdir "$YARAX_PREFIX/lib"
)
export PKG_CONFIG_PATH="$YARAX_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH="$YARAX_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
version="$(pkg-config --modversion yara_x_capi)"
test "$version" = '1.23.0' || { echo "Wrong YARA-X C API version: $version" >&2; exit 2; }
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 2
python3 scripts/native_yarax_smoke.py --scanner build/scanner/vulnimprint-scan
