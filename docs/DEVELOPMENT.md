# Build and test

The supported development and release environment is Ubuntu 22.04 x86-64,
Python 3.12+, C++20 compiler, CMake, Ninja, pkg-config, Rust/Cargo,
cargo-c, binutils and the pinned ELFIO and YARA-X Git submodules. The
GCC/Clang research matrix requires GCC 11/12 and Clang 14/15.

```bash
git clone --recurse-submodules https://github.com/Andrew-Job/vuln_imprint.git
cd vuln_imprint
python scripts/verify_dependencies.py --require-checkout
python3 -m pip install -r requirements-dev.txt
make format-check
make test
bash scripts/bootstrap_yarax.sh
bash scripts/build_yarax_python.sh
make test-native
```

`make test` runs independent Python tests; `make test-native` additionally
requires the actual pinned native scanner and YARA-X Python extension.
Missing required dependencies fail the corresponding test suite; skipped
tests are not allowed. No mock may substitute for native CVE validation.

The C++ `clang-format` 19.x configuration is based on Google and has an
explicit **four-space** indentation override. Python YAPF uses the pinned
Google preset (four spaces). `make format` rewrites first-party source only;
`make format-check` is a full-source formatting check. Never reformat Git
submodules.

## Research vs admission vs release

Factory-generated proposals and manual masks are research inputs. They do
not enter the production DB until technical review and actual native
independent affected/fixed/backport/unrelated testing. The `native` CI job
runs the corpus gate for all Git-admitted CVEs. Its input is pinned by SHA-256
in `release/reviewed-corpus.lock.json` and downloaded only from the hostname
set by the protected `VULNIMPRINT_CORPUS_HOST` repository variable. The
corpus contains third-party executable evidence and must not be committed
to this repository. It is **not** a user database.

The version-tag workflow checks prior successful CI for the exact main
commit, builds the compiled database from `signatures/validated/`, packages
one application archive, creates SBOM and content attestations, and verifies
staged and downloaded artifacts. It does not repeat research or mask mining.

Source archives without Git submodule contents are not sufficient for native
builds; use the recursive Git checkout and dependency verification.

Execute untrusted upstream build recipes in disposable isolated environments
without secrets, publication credentials, privileged host mounts or
repository write permissions. The Factory does not sandbox arbitrary
`commands` itself; external recipes must be independently reviewed and
run only in controlled research environments. Do not represent untrusted
manifest execution as safe on a developer workstation.
