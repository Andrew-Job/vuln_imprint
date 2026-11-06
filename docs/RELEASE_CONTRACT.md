# Admission and release contract

This document describes enforced requirements for the supported
profile. Approved CVE signatures are source files, **not** GitHub Actions
artifacts. Every admitted CVE in `signatures/validated/` enters the next
release; no separate release selection file exists.

## Supported profile

The current scanner processes ELF64 little-endian x86-64 binaries on Linux.
The production database profile identifier is `linux-elf64-x86_64-sysv`.
Architecture/format support is extensible but never inferred from the
presence of a compatible-looking YARA-X signature. Unsupported and damaged
inputs produce explicit scan errors, including under `--all-sections`.

## CVE admission before merging into `main`

Each admitted CVE has exactly three version-controlled files:

```text
signatures/validated/CVE-YYYY-NNNN/
    pack.json
    rules-exec.yar
    reviewed-evidence.json
```

The rule must contain the vulnerable implementation's machine-code evidence,
not just a library/version fingerprint. Manual byte masks are permitted, but
any change invalidates previous validation. The reviewed evidence binds the
canonical `pack.json` and `.yar` SHA-256, primary patch-state sources, sample
labels and binary SHA-256, independent training/holdout lineages, and exact
measured compiler identities where available.

Approval requires native YARA-X tests on independently labeled affected,
fixed, same-version backported and unrelated binaries. `tools.production_db
build` validates a complete case corpus, including the consolidated database.
The first profile's existing native gate requires two independent affected,
two independent fixed, one backport, twenty unrelated specimens per CVE,
versioned GCC 11/12 and Clang 14/15 affected/fixed `-O2` and `-O3` lanes, and
at least one genuine stripped statically linked third-party affected sample
across the included cases. Sample provenance and patch-state correctness still
require an independent human reviewer; a native match alone cannot prove the
semantic vulnerability. The `reviewed-evidence.json` schema version is `2`.

Review corpora must not be committed as third-party executable binaries. The
protected CI native admission job fetches a checksum-pinned corpus from an
administrator-approved HTTPS hostname. `release/reviewed-corpus.lock.json`
contains `schema_version: 2`, `archive_url` and `archive_sha256`; the repository
variable `VULNIMPRINT_CORPUS_HOST` authorizes the hostname. The corpus archive
is *validation input only*: its embedded canonical files must match the Git
source byte-for-byte. No temporary GitHub Actions artifact is required.
Incomplete/missing/corrupt specimens, empty evidence, unsupported variants,
false positives, false negatives and incomplete native scans block merge.

The archived binary corpus is not a second signature database and is never
installed on user systems. No CVE is production-ready merely because a
research `.yar` file parses. The libpng research candidates shipped separately
under `signatures/candidates/` remain `CANDIDATE_ONLY`; approval requires the
independent evidence described above. Their existing offline observations and
source-only checks are not sufficient to move them to `validated/`.

## Building a release

A production release requires at least one admitted CVE and a successful
required CI run for the **exact** protected `main` source SHA. Release tags must
be protected. `tools.production_db assemble` reads **all** directories under
`signatures/validated/`, validates each canonical pack and review digest,
compiles one YARA-X database through the native scanner, then verifies the
compiled database. No release-time specimen download or extra CVE selection
is performed; affected/fixed/backport admission was done before merge.

One downloadable application archive contains the C++ scanner, bundled YARA-X
C API library, complete compiled database, index, integrity manifests and
license notices. The release also contains `SBOM.spdx.json`,
`release-contents.json` and `SHA256SUMS`. The release-content statement binds
every CVE's pack/rule SHA-256, the index/manifest digests found inside that
single application archive, the source Git commit, and the two payload assets
(application archive and SBOM). `release-contents.json` and `SHA256SUMS` are
independently attested release assets, but are not entries in the content
statement: the statement cannot bind its own digest without a circular hash.
GitHub Attestations sign finalized release assets using the protected
publisher workflow and short-lived Sigstore/OIDC identity; per-CVE signing is
not required.

Before making a draft release public, the workflow checks staged bytes,
local database verification, clean installed scanning, provenance attestations
for every release asset, the product archive's SBOM attestation, byte-for-byte
equality of downloaded draft assets with the locally attested files, SHA-256,
and a second clean installed scanner smoke on the downloaded archive.
`gh release verify` requires a published immutable
release and therefore executes *after* publication; it is a post-publication
check, not a prepublication gate. The publisher verifies all four release
assets against the immutable published release.

Missing CVEs, native YARA-X, SBOM, publisher provenance, source CI, repository
protection or runtime checks prevent publishing. A successful publication is
not evidence that untested compiler variants or other binary formats are
covered.

## Dependency and runtime trust

The current application is built on Ubuntu 22.04 x86-64. Its native binary
depends on a compatible Linux loader, glibc and OpenSSL runtime. The bundle
ships the YARA-X C API shared library; it is not a fully static Linux binary.
Release CI checks dynamic loader resolution in the staging directory and
runs a clean installed smoke in the runner environment. Portability to other
Linux distributions is not implicitly certified by this check.

An end user upgrades **the application and its database together** by
installing another verified GitHub Release. There is no separately supported
remote DB updater, version-store API, or automatic rollback subsystem.
Identity verification happens before unpacking; the installed launcher
verifies the bundled database SHA-256 before every scan.
