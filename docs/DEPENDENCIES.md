# Dependency and upstream update policy

## Recursive Git checkout

The native YARA-X engine and the ELFIO C++ parser are **separate Git submodules**, not floating `git clone --branch` invocations. Every VulnImprint commit records the exact upstream Git commit as a gitlink (`mode 160000`) and repeats it in `external/DEPENDENCIES.json` for automated consistency checks.

```bash
git clone --recurse-submodules https://github.com/Andrew-Job/vuln_imprint.git
cd vuln_imprint
git submodule status --recursive
python3 scripts/verify_dependencies.py --require-checkout
```

Existing clones:

```bash
git submodule sync --recursive
git submodule update --init --recursive
python3 scripts/verify_dependencies.py --require-checkout
```

The C++ scanner uses header-only [ELFIO](https://github.com/serge1/ELFIO) Release_3.12 at upstream commit `8ae6cec5d60495822ecd57d736f66149da9b1830` in `external/elfio`. No upstream header is copied into VulnImprint source. CMake includes the submodule directly; the product includes ELFIO MIT license text.

The matching dependency, statically linked into the release Scanner through the official C API, is VirusTotal YARA-X **v1.23.0**, commit `afe4585b12f56c698794dc80b3d28ddb87b56c0a`. The pinned SHA identifies the source tree used by the native build. Nested Git submodules, if any, are fetched recursively. Cargo resolves Rust dependency versions using the pinned upstream `Cargo.lock`. The build toolchain is pinned to Rust **1.99.1** via `rust-toolchain.toml`, and `cargo-c` **0.10.26**; changing either is a reviewed dependency upgrade. Native CI builds the C API and its Python `yara_x` binding using `scripts/build_yarax_python.sh` from **the same pinned source** (pinned `maturin==1.16.0`). No independently floating PyPI YARA-X wheel is accepted in these integration checks. `verify_dependencies.py --require-checkout` also validates the initialized status of every nested submodule.

## Deliberate upgrades

1. Review the new upstream release, security advisories and API/ABI changes.
2. Update the relevant dependency (`external/yara-x` or `external/elfio`) to the selected exact upstream commit; for YARA-X use `git -C external/yara-x fetch --tags && git -C external/yara-x checkout --detach <full-sha>`.
3. In the same PR, update `external/DEPENDENCIES.json`, affected CMake checks, downstream documentation and licenses as appropriate.
4. Run the complete native CI, compiled database serialization/deserialization, independent affected/fixed/backport corpus and clean installed-bundle tests.
5. Publish a new complete application release. Never replace a published compiled DB with one built against a different engine without versioning it.

Do **not** run `git submodule update --remote` on a release branch: it advances to a floating branch head and invalidates reproducibility. Do not vendor any second copy of YARA-X or ELFIO.

## CVE source code is different

The Factory can need **two or more revisions of the same library at the same time**, for affected/fixed/backported tests. Those source repositories are fetched into a content-addressed research workspace from each CVE manifest and pinned to full source commits (with hash and build provenance). A single zlib/libpng Git submodule could not represent all simultaneous CVE patch states and is therefore intentionally **not** used for fixture acquisition.

## Factory Git mirror and specimen cache

Factory source recipes require a full pinned Git commit and use isolated
checkouts under the job's work directory. An optional shared mirror is selected
with `VULNIMPRINT_GIT_MIRROR_CACHE` or the Factory API's `mirror_cache`
argument. Mirror identity is SHA-256 of the exact source locator; checkout
identity also includes the pinned commit. The mirror retains existing Git
objects and fetches only if the requested commit is missing. Mirror updates
and checkout creation are serialized with local file locks. A mirror with an
unexpected origin and a checkout with local changes or a different HEAD are
rejected, never silently reset. The cache is not authoritative for unpinned
refs and does not sandbox source-build commands.

The Factory's local artifact store keys binary blobs by their complete SHA-256
and verifies their content on use. Record metadata is published atomically.
Cached objects may be deleted and recreated from their verified sources;
cache presence alone is never evidence of CVE accuracy or upstream trust.

## Factory parsing and release SBOM (pinned dependencies)

- `requirements-factory.txt` pins **pyelftools 0.33** and **Capstone 5.0.9**.
  Installed from PyPI for Python/native test jobs. These
  are build/research tools, not runtime components of the distributed scanner.
  No separate Git submodule checkout is needed for versioned Python wheels.
- `scripts/install_syft.sh` downloads the upstream **Syft 1.57.0** Linux
  x86-64 archive from `anchore/syft`, checks the immutable GitHub release and
  the downloaded archive's release attestation, then verifies the SHA-256
  published in that release's checksum list. GitHub CLI and authorization are
  required for this verification. Syft is build-time only.
- The product archive includes the pinned upstream YARA-X `Cargo.lock` so Syft
  can discover Rust dependencies from the *shipped* provenance material. The
  SPDX document is generated from the finalized product archive and then
  included in the signed release asset manifest.
- Any version update must include a relevant first-party integration test and
  a license/security review.
