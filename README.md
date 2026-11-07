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
- **Versioned signature database**: CVE-owned DB records under `signatures/`
  are combined into a compiled YARA-X database. Each record has one owning
  CVE and one of two database channels: `test` or `production`.

**Current scan target:** Linux ELF64, little-endian x86-64. Unsupported or
invalid inputs fail explicitly, including with the diagnostic
`--all-sections` switch. The intended architecture can expand to other
formats and CPUs, but these are not implemented scanner capabilities yet.

The scanner reports `file` as display-oriented UTF-8 and `file_bytes_hex`
as the lossless encoding of the Linux pathname bytes.

## Database review and assembly

When independent evidence is available, it binds `record_id`, canonical
`record_sha256` and explicit `sample_ids` to each reviewed record. The
`python -m tools.production_db review` command validates this evidence
without producing a database. The only database builder is
`python -m tools.production_db assemble`, which reads Git-tracked CVE records.
At present no production CVE has independent reviewed evidence; source
validation and successful YARA-X compilation must not be read as proof of
CVE detection accuracy.

## Distribution and verification

GitHub Releases distributes one application tarball containing the native
scanner with statically linked YARA-X, compiled database, index, checksum
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
linked to the Linux system runtime; current release builds use Ubuntu 24.04
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

The native build obtains pinned Git submodules and compiles the official
YARA-X C API with Rust/Cargo. It has no fallback matcher. See
[Development](docs/DEVELOPMENT.md) for prerequisites and real-engine checks.

## CVE research and database records

The authoritative source is `signatures/`. CVE is the authoring and
maintenance unit. Each CVE pack may contain multiple independent DB records;
each record belongs to exactly one CVE and has a stable `record_id`. If the
same byte pattern applies to another CVE, it is duplicated into a separate
record under that CVE. This intentional duplication allows records to be
edited and maintained independently.

Only two database channels exist: `test` and `production`. Test database
assembly includes both channels; production releases include only production
records. The channel is an inclusion target, not a correctness grade. All five
current machine-record CVEs (25 patterns) are assigned to `production`; the
sixth CVE remains research-only with no machine record. These assignments do
not assert that the detectors have independently verified CVE accuracy or exploitability.

A pack uses schema version 3 and stores one top-level `cve` with a `records`
array. Each YARA rule reports exactly one CVE and one record ID. Scanner output
counts unique CVEs separately from record matches and pattern hits.

To create a manual record, use `tools.manual_rules init`; new records default
to the `test` channel. Use a distinct `--record-key` for additional records
under the same CVE. Source lint, native compilation, and release integrity are mandatory.
Evidence validation is record-specific and does not change record channels.

For automated research, see `scripts/create_catalog.py`, `cli.py batch` and
[Toolchain matrix](docs/TOOLCHAIN_MATRIX.md).

## Repository map

```text
scanner/        native scanner and ELFIO adapter
factory/        binary evidence and candidate generation
signatures/     Git-tracked CVE packs and independently owned DB records
tools/          CVE source validation, complete DB assembly and release packaging
scripts/        native build, checks and research helpers
tests/          Factory behavior tests
tests_release/  first-party DB and packaging contract tests
tests_integration/ native integration tests
.github/        CI and publication workflows
```

Source under MIT; pinned third-party YARA-X and ELFIO retain their own
licenses. See [Security](SECURITY.md), [Contributing](CONTRIBUTING.md),
[Dependency policy](docs/DEPENDENCIES.md) and [Third-party notices](THIRD_PARTY_NOTICE.md).
