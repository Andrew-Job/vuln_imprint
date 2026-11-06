# VulnImprint

**Find vulnerable code, not just vulnerable versions.**

VulnImprint searches machine-code patterns corresponding to known vulnerable
implementations inside compiled binary files. Detection is not derived solely
from library name or package version. A match does not prove exploitability;
absence of a match is not proof of safety.

## Current implementation

- **Scanner**: C++20, ELFIO and official YARA-X C API, binary matching and JSON
  reports with file offsets, CVE identifiers and explicit scan errors.
- **Signature Factory**: Python 3.12+, pinned source acquisition, GCC/Clang
  build profiles, disassembly, candidate masks and independent validation.
- **Production database**: every technically approved CVE under
  `signatures/validated/` is combined into one compiled YARA-X database.

**Current scan target:** Linux ELF64, little-endian x86-64. Unsupported or
invalid inputs fail explicitly, including with the diagnostic
`--all-sections` switch. The intended architecture can expand to other
formats and CPUs, but these are not implemented scanner capabilities yet.

The scanner reports `file` as display-oriented UTF-8 and `file_bytes_hex`
as the lossless encoding of the Linux pathname bytes.

## Distribution and verification

GitHub Releases distributes one application tarball containing the native
scanner, bundled YARA-X shared library, compiled database, index, checksum
manifests and license notices. The release also publishes three companion
assets: `SBOM.spdx.json`, `release-contents.json` and `SHA256SUMS`. There is
no separately installed database or automatic DB updater: install a new
verified complete release to update signatures.

After a published release exists, download **all four assets** for the same
tag from its GitHub Release page. Verify GitHub Artifact Attestations for all
four assets and the SPDX SBOM attestation for the application archive as
described in [Release signing](docs/RELEASE_SIGNING.md). Then:

```bash
sha256sum --check SHA256SUMS
tar -xzf vulnimprint-linux-x86_64.tar.gz
./vulnimprint/bin/vulnimprint version
./vulnimprint/bin/vulnimprint scan --json /path/to/program.elf
```

A `SHA256SUMS` file by itself does not authenticate its publisher. The installed
launcher checks the embedded database hashes before each scan. End users
need no Python, Cargo, or Factory installation. The bundle is dynamically
linked to the Linux system runtime; current release builds use Ubuntu 22.04
x86-64 and require a compatible glibc/OpenSSL environment. Compatibility
with arbitrary Linux distributions is not promised.

## Development

```bash
git clone --recurse-submodules https://github.com/Andrew-Job/vuln_imprint.git
cd vuln_imprint
python3 -m pip install -r requirements-dev.txt
bash scripts/bootstrap_yarax.sh
bash scripts/build_yarax_python.sh
make test-native
```

The native build obtains pinned Git submodules and requires the actual C++
YARA-X C API; it has no fallback matcher. See [Development](docs/DEVELOPMENT.md)
and [Native build](docs/YARAX_NATIVE_BUILD.md).

## CVE research and approval

The production source of truth is `signatures/validated/`, with exactly three
files per approved CVE: `pack.json`, `rules-exec.yar` and
`reviewed-evidence.json`. Changes are accepted through reviewed PRs after
independent affected/fixed/backport/unrelated native validation. Every
approved CVE automatically enters the next compiled release database.
Multiple machine patterns for the same CVE represent alternatives.

The included libpng dossier in `signatures/candidates/` contains five
**unapproved** research candidates. Its source/anchor checks are not evidence
of native YARA-X affected/fixed/backport accuracy. No candidate has been
promoted merely because its `.yar` syntax is valid. An empty Git-validated
source tree correctly blocks a production release. Candidates can only be
approved after the actual independent corpus and technical review satisfy
the [Admission contract](docs/RELEASE_CONTRACT.md).

Manual mask edits are welcome and must be revalidated. The Factory experimental
matrix includes GCC 11/12 and Clang 14/15 at `-O2` and `-O3`; tested profiles
and toolchain digests are preserved as evidence rather than universal claims.
A researcher may start from:

```bash
python3 -m tools.manual_rules init \
  --cve CVE-2022-37434 \
  --hex 'AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66 77 88 99 00 11' \
  --output run/cve-proposals/CVE-2022-37434
python3 -m tools.manual_rules lint --directory run/cve-proposals/CVE-2022-37434
```

The bytes are illustrative syntax only, **not** a detector for the named CVE.
For automated research, see `scripts/create_catalog.py`, `cli.py batch` and
[Toolchain matrix](docs/TOOLCHAIN_MATRIX.md).

## Repository map

```text
scanner/        native scanner and ELFIO adapter
factory/        binary evidence and candidate generation
signatures/     reviewed production rules and isolated research candidates
tools/          rule admission, complete DB assembly and release packaging
scripts/        native build, checks and research helpers
tests/          Factory behavior tests
tests_release/  first-party DB and packaging contract tests
tests_integration/ native integration tests
.github/        CI and publication workflows
```

Source under MIT; pinned third-party YARA-X and ELFIO retain their own
licenses. See [Security](SECURITY.md), [Contributing](CONTRIBUTING.md),
[Dependency policy](docs/DEPENDENCIES.md) and [Third-party notices](THIRD_PARTY_NOTICE.md).
