# Development, native build and testing

## Supported build environment

Release builds target Ubuntu 24.04 x86-64. They require a C++20 compiler,
CMake, Ninja, `pkg-config`, OpenSSL development headers, GNU binutils,
Python 3.12+, Rust 1.99.1, `cargo-c` 0.10.26 and the pinned Git submodules:
ELFIO 3.12 and YARA-X 1.23.0. The native scanner uses the official YARA-X
C API and does not support an alternative matching engine.

A source archive containing YARA-X is **not** a built YARA-X library. The
native build uses Cargo and the upstream `Cargo.lock` to resolve Rust crates,
compiles `libyara_x_capi.a` with the upstream `release-lto` profile, then
statically links the C++ scanner against it. The first build requires access to the pinned Rust toolchain, Cargo crates and
upstream Git submodules; it cannot be performed from only the two source ZIPs
on a machine without Rust/Cargo and a populated crate cache.

```bash
git clone --recurse-submodules https://github.com/Andrew-Job/vuln_imprint.git
cd vuln_imprint
python3 scripts/verify_dependencies.py --require-checkout
python3 -m pip install -r requirements-dev.txt
bash scripts/bootstrap_yarax.sh
bash scripts/build_yarax_python.sh
make test-native
```

`bootstrap_yarax.sh` verifies the submodules, obtains the pinned Rust toolchain
and `cargo-c`, builds and installs the official YARA-X C API, builds the
scanner through CMake and runs `scripts/native_yarax_smoke.py` against the
real engine. It installs the library under `${YARAX_PREFIX:-$HOME/.local}`;
the script exports `PKG_CONFIG_PATH` to locate its static linking metadata.
For a later manual CMake invocation, set `PKG_CONFIG_PATH` to the installed
`lib/pkgconfig` directory. No YARA-X `LD_LIBRARY_PATH` is necessary.

`build_yarax_python.sh` builds the Python binding from the same pinned YARA-X
source for Factory integration. An independently downloaded YARA-X wheel or
a simulated matcher is not an acceptable substitute for this integration.
To build only the C API before invoking CMake directly, use
`bash scripts/bootstrap_yarax.sh --capi-only`.

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
python -m scripts.check_signature_sources
python -m tools.production_db assemble --signatures signatures \
  --channel test --output build/db-test \
  --scanner build/scanner/vulnimprint-scan
python -m tools.production_db verify --database build/db-test \
  --scanner build/scanner/vulnimprint-scan
```

`make test` executes first-party Python and release contract tests.
`make test-native` additionally executes integration tests requiring the
native ELFIO adapter and installed YARA-X Python binding. A skipped mandatory
test is an error. The YARA-X C API smoke test is separately executed by
`bootstrap_yarax.sh` and by native CI.

Native CI also compiles and scans a generated ELF using **the actual production
CVE rules** to verify record identifiers, pattern offsets and executable-range
selection. This verifies the adapter and concrete database content, not
whether those patterns distinguish affected from fixed third-party binaries.

The `scripts.check_signature_sources` source check validates the retained
25 production patterns and their 15 recorded original machine-code anchors
without running YARA-X. Independent CVE accuracy requires affected, fixed,
backport and unrelated sample controls bound to each `record_sha256`.
`production_db review` checks those records independently. The current
source tree contains no reviewed evidence artifacts, so no independently
confirmed CVE detection accuracy is claimed. The optional reviewed-corpus
CI stage reports this condition explicitly rather than asserting a pass.

`make test-coverage` reports first-party Python coverage for diagnostics; no
coverage percentage proves CVE accuracy. No duplicate test suite for YARA-X,
ELFIO, GCC or other external projects is required. Tests must exercise a
first-party behavior, contract or established failure mode.

For supported compiler research lanes, versions, provenance and independent
holdout requirements, see [Toolchain matrix](TOOLCHAIN_MATRIX.md).

## Security and release boundaries

The release workflow builds the production-channel records from the
Git-tracked `signatures/` tree and packages the statically linked scanner and
database together. The product does not carry a YARA-X `.so` dependency;
compatible Linux system runtime libraries may remain dynamically linked.
Publishing requires the verified build, attested artifacts and approved
repository protections. The database inclusion channel is not an accuracy or
exploitability grade.

Run untrusted upstream source-build recipes only in disposable isolated
research environments without secrets, publication credentials or privileged
host mounts. Factory does not itself sandbox arbitrary recipe commands.
