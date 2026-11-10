# Development, native build and testing

## Reference native build environment

The release CI uses Ubuntu 24.04 x86-64, a C++20 compiler, CMake, Ninja,
`pkg-config`, OpenSSL development headers, GNU binutils, Python 3.12+,
Rust 1.99.1, `cargo-c` 0.10.26 and the pinned Git submodules ELFIO 3.12 and
YARA-X 1.23.0. The native Scanner uses
the official YARA-X C API.

A source archive does not contain a compiled C API. VulnImprint builds
`libyara_x_capi.a` from the pinned YARA-X submodule using its `release-lto`
Cargo profile, then links the C++ Scanner against the resulting static
library. Building from source requires the Rust toolchain and Cargo crates.

```bash
git clone --recurse-submodules https://github.com/Andrew-Job/vuln_imprint.git
cd vuln_imprint
python3 -m pip install -r requirements-dev.txt
rustup toolchain install 1.99.1 --profile minimal
cargo +1.99.1 install cargo-c --version 0.10.26 --locked
bash scripts/bootstrap_yarax.sh
bash scripts/build_yarax_python.sh
make test-native
```

`bootstrap_yarax.sh` builds and installs the pinned YARA-X C API, builds the
Scanner with CMake, and runs a native integration smoke test. Use `--capi-only`
to build only the C API. The script expects initialized Git submodules and an
installed Rust toolchain with `cargo-c`; it does not modify the toolchain or
fetch Git sources. The library is installed under
`${YARAX_PREFIX:-$HOME/.local}`. For direct CMake invocation, point
`PKG_CONFIG_PATH` to that prefix's `lib/pkgconfig` directory. The Scanner
has no dynamic `libyara_x_capi.so` dependency.

`build_yarax_python.sh` builds the Python binding from the same pinned YARA-X
source using Maturin. It uses the `release-lto` Cargo profile and the same
target directory as the C API to reuse compiled Rust dependencies. An
independently downloaded Python wheel is not used for this integration.

## First-party formatting

C++ uses the Google `clang-format` preset with four-space indentation in
`.clang-format`; Python uses YAPF's Google preset in `.style.yapf`.
The formatter versions are pinned in `requirements-format.txt`, separately
from the runtime and test dependencies. On macOS, the corresponding
command-line tools can also be installed with Homebrew.

```bash
python3 -m pip install -r requirements-format.txt
make format
make format-check
```

The Makefile calls `clang-format` and `yapf` executables directly, not
`python -m yapf`. Neither target formats `external/` submodules or generated
databases. A formatting run does not establish test or CI success.

## Functional verification

```bash
make test
make test-native
python -m scripts.check_cve_source_tree
python -m tools.production_db assemble --signatures signatures \
  --channel test --output build/db-test \
  --scanner build/scanner/vulnimprint-scan
python -m tools.production_db verify --database build/db-test \
  --scanner build/scanner/vulnimprint-scan
```

`make test` executes first-party Python functionality, database and packaging
tests. `make test-native` additionally executes integration tests requiring
the native ELFIO adapter and installed YARA-X Python binding. A skipped
mandatory test is an error. The YARA-X C API smoke test is separately
executed by `bootstrap_yarax.sh` and by native CI.

Native CI tests Scanner matching and executable-range handling using a
small selection of CVEs read directly from production records. This does not
establish vulnerability-detection accuracy. See the
[research evidence](research/libpng-elf64-x86_64/README.md) for recorded
specimens and observations.

The separate `production_db review` workflow accepts per-record affected,
fixed and unrelated sample controls bound to each `record_sha256`. This
structured review workflow is distinct from specimen research and the
product's native integration tests.

Install `requirements-coverage.txt` to collect coverage locally with
`make test-coverage`. Coverage percentages do not establish CVE accuracy.
Tests exercise VulnImprint behavior and failure modes, not dependencies or
GitHub workflow settings.

For compiler research lanes, versions, provenance and independent holdout
requirements, see [Toolchain matrix](TOOLCHAIN_MATRIX.md).

## Security and release boundaries

The release workflow assembles production-channel records from the
Git-tracked `signatures/` tree and packages the statically linked Scanner
and database together. The Scanner does not carry a YARA-X `.so` dependency;
system runtime libraries may remain dynamically linked.

Publishing requires a verified build and artifact attestations. GitHub
branch, tag and environment protections are configured by repository
administrators rather than rechecked by workflow scripts. The database
inclusion channel is not an accuracy or exploitability grade.

Run untrusted upstream source-build recipes only in disposable isolated
research environments without secrets, publication credentials or privileged
host mounts. Factory does not itself sandbox arbitrary recipe commands.
