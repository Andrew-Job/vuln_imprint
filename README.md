# <img src="assets/vulnimprint-icon.png" alt="VulnImprint logo" width="44" height="44" align="absmiddle"> VulnImprint

**Find CVE-related machine-code patterns, not just version strings.**

VulnImprint is an extensible static scanner for identifying machine-code
signatures associated with known CVEs in compiled binaries. It examines
executable code and reports the matching CVE, independently maintained
signature record, machine-code pattern and original file offset.

The native Scanner and its compiled production signature database are
distributed together. This repository also contains the Signature Factory and
source records used to research, validate and contribute detections.

[Quick start](#quick-start) ·
[Create a CVE signature](docs/CREATING_AND_VALIDATING_CVE_MASKS.md) ·
[Contribute a CVE](https://github.com/Andrew-Job/vuln_imprint/issues/new?template=cve_signature.yml) ·
[Roadmap](docs/ROADMAP.md)

## Quick start

From the repository's **Releases** section, download these four assets
for the Linux x86-64 package into the same directory:

- `vulnimprint-linux-x86_64.tar.gz`
- `SHA256SUMS`
- `SBOM.spdx.json`
- `release-contents.json`

On a compatible Linux x86-64 system, verify and extract the archive, then run:

```bash
sha256sum --check SHA256SUMS
tar -xzf vulnimprint-linux-x86_64.tar.gz
./vulnimprint/bin/vulnimprint version
./vulnimprint/bin/vulnimprint scan --json ./vulnimprint/bin/vulnimprint-scan
```

The example scans the native scanner executable included in the archive.
Replace its path with a binary you want to inspect, or use `--recursive` to
scan a directory. Findings are returned as JSON. The distributed scanner
and signature database do not require a separate Factory installation.

The current Scanner supports Linux ELF64 x86-64 (System V AMD64 ABI),
including `ET_REL`, `ET_EXEC` and `ET_DYN`. Additional platforms and
architectures are open for contributions. The Linux package requires a
compatible system runtime, including glibc and OpenSSL. See
[Release verification](docs/RELEASE_SIGNING.md) for provenance and SBOM checks.

## How VulnImprint works

VulnImprint matches machine-code signatures in executable regions, rather
than inferring vulnerability status from component version strings alone.
Its results identify individual CVEs and records so that detections can be
reviewed, reproduced and improved independently.

- **Scanner:** examines supported executable formats and maps matches back to
  original file offsets using YARA-X rules.
- **Signature database:** stores CVE-owned records, each with its own identity,
  platform profile and alternative machine-code patterns.
- **Signature Factory:** supports source provenance, compiler-aware research,
  disassembly, pattern generation and validation.

The [CVE source tree](signatures/README.md) contains the maintained records.
The compiled database accompanying each release is the authoritative catalog
of detections included in that release. See [Database](docs/DATABASE.md) for
the record model and [Architecture](docs/ARCHITECTURE.md) for the processing
pipeline.

## Contribute

**Know a CVE we should detect?**
[Propose a signature or report a missing match](https://github.com/Andrew-Job/vuln_imprint/issues/new?template=cve_signature.yml).
A CVE identifier, public reference or reproducible binary test is enough to
start a discussion; a finished machine-code signature is not required.

To create a machine-code signature, follow the
[step-by-step CVE guide](docs/CREATING_AND_VALIDATING_CVE_MASKS.md).

Contributions can add CVE records, improve patterns across compiler and build
variants, test detections on real binaries, extend executable-format and
architecture support, or improve Scanner and Factory. See
[Contributing](CONTRIBUTING.md), the [signature source tree](signatures/README.md)
and [open issues](https://github.com/Andrew-Job/vuln_imprint/issues).
Pull requests are reviewed by the maintainer.

## Development

The Scanner is implemented in C++20 with the official YARA-X C API. The
Python Signature Factory supports the research and validation workflow.
CVE-owned source records are maintained in Git and assembled into the
compiled database distributed with each release.

See [Architecture](docs/ARCHITECTURE.md), [Database](docs/DATABASE.md),
[Development](docs/DEVELOPMENT.md) and the [Roadmap](docs/ROADMAP.md).

VulnImprint is licensed under MIT. See [Security](SECURITY.md),
[Dependencies](docs/DEPENDENCIES.md) and
[Third-party notices](THIRD_PARTY_NOTICE.md).
