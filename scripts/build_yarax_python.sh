#!/usr/bin/env bash
# Build the Python YARA-X binding from the SAME pinned Git submodule as the
# official C API used by the native scanner. No separately sourced wheel.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
python3 scripts/verify_dependencies.py --require-checkout
# Keep maturin on the exact Rust toolchain used for the C API build.
export RUSTUP_TOOLCHAIN=1.99.1
rustup run "$RUSTUP_TOOLCHAIN" cargo --version >/dev/null
export CARGO_TARGET_DIR="$root/external/yara-x/target"
python3 -m pip install 'maturin==1.16.0'
wheels="$(mktemp -d)"
trap 'rm -rf "$wheels"' EXIT
maturin build --manifest-path external/yara-x/py/Cargo.toml \
  --release --locked --interpreter "$(command -v python3)" --out "$wheels"
shopt -s nullglob
built=("$wheels"/yara_x-*.whl)
if (( ${#built[@]} != 1 )); then
  echo "Expected exactly one YARA-X Python wheel, found ${#built[@]}" >&2
  exit 2
fi
python3 -m pip install --no-deps --force-reinstall "${built[0]}"
python3 - <<'PYVALIDATE'
import importlib.metadata
import yara_x
expected = '1.23.0'
actual = importlib.metadata.version('yara-x')
assert actual == expected, f'Python YARA-X version mismatch: {actual} != {expected}'
assert callable(yara_x.compile), 'missing YARA-X compile API'
print('Pinned source-built YARA-X Python API:', actual)
PYVALIDATE
