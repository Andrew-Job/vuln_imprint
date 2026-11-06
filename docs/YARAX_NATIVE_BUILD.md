# YARA-X 1.23.0: upstream source integration and acceptance

This repository uses the **upstream YARA-X C API**, not a fork, reimplementation,
mock, or Python extension in the release scanner. Its pinned source is a Git
submodule at `external/yara-x`, recorded by the superproject **gitlink** and
`external/DEPENDENCIES.json`.

## Obtain the recursive upstream sources

```bash
git clone --recurse-submodules https://github.com/Andrew-Job/vuln_imprint.git
cd vuln_imprint
python3 scripts/verify_dependencies.py --require-checkout
```

An ordinary GitHub-generated source ZIP, a `git archive`, and the Git bundle of
only this repository **do not include Git submodule contents**. To fill a
previously cloned checkout, run:

```bash
git submodule update --init --recursive
python3 scripts/verify_dependencies.py --require-checkout
```

The source commit must be exactly
`afe4585b12f56c698794dc80b3d28ddb87b56c0a` (YARA-X v1.23.0).
The verifier also checks the checked-out sources and nested Git submodule
states. The first Cargo build additionally needs the pinned Rust crates from
`Cargo.lock`; fetching the Git submodule alone is **not** a fully offline Rust
build. Follow the upstream licenses and preserve the BSD-3-Clause notices.

## Native build and mandatory smoke test

On an internet-connected Linux x86-64 machine with C/C++, CMake, Ninja,
`pkg-config`, `libssl-dev`, Rustup and Python 3 available:

```bash
bash scripts/bootstrap_yarax.sh
```

This command checks the recursive source revision, installs the pinned Rust
1.99.1 toolchain and cargo-c 0.10.26, runs `cargo cinstall` against the
**submodule sources** using the upstream lockfile, builds `vulnimprint-scan`
with the generated `yara_x.h`, and executes a real C++/YARA-X C API test.
The installed YARA-X library must report **version 1.23.0** via pkg-config.

The smoke test requires real code execution of the native scanner and checks:

1. Compile a rule into a serialized `.yarc` database, verify/deserialize it,
   and report exactly one rule and the correct DB SHA-256.
2. Detect an actual instruction byte sequence in a **stripped** ELF with the
   correct matched byte offset, length, metadata and executable flag.
3. Obtain the same result from the source `.yar` and compiled `.yarc` paths.
4. Report zero hits for a negative ELF and zero executable hits when the marker
   is present only in `.rodata`; whole-file scanning must find the latter.
5. Use multiple scanner threads on a directory of separate ELF files without
   leaking previous scan results between files.
6. Reject a corrupted compiled database instead of accepting it silently.

The CI `native` job runs this test. The **release** job also executes the
native test before compiling the database from Git-approved CVE rules. A release is blocked if
YARA-X cannot be built, linked, loaded or tested. The native test cannot be skipped or replaced with Python binding tests.
Run `python -m pytest -q tests_integration` after building the pinned Python
binding to verify the VulnImprint Factory adapter as a separate integration.

## Verified vs unverified

An installed Rust toolchain, checked-out submodule and a successful build of
`libyara_x_capi` are prerequisites; verifying only the Git commit and checking
C++ source syntax does **not** prove native compatibility. Even a passing
smoke test confirms runtime integration, not CVE-specific accuracy.
The CVE evidence gate and actual affected/fixed/backport holdouts are separate.

The scanner supports ELF64 x86-64 executable regions.
It intentionally supports the restricted `any of them` binary-pattern rule
subset; arbitrary YARA conditions across different segments or whole-file
modules are not faithfully evaluated in segment-by-segment mode. Do not admit
such rules into production until the scan semantics are extended and tested.
