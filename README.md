# <img src="assets/vulnimprint-icon.png" alt="VulnImprint logo" width="44" height="44" align="absmiddle"> VulnImprint

**Find CVE-related machine-code patterns, not just version strings.**

VulnImprint scans compiled binaries for signatures associated with known CVEs.
It examines executable code and reports which CVE, signature record and pattern
matched, including the original file offset. The native scanner and compiled
signature database ship together; this repository also contains the tools for
researching and contributing new signatures.

[Quick start](#quick-start) ·
[Contribute a CVE](https://github.com/Andrew-Job/vuln_imprint/issues/new?template=cve_signature.yml) ·
[Roadmap](docs/ROADMAP.md)

## Quick start

From the repository's **Releases** section, download these four files from
the same release into one directory:

- `vulnimprint-linux-x86_64.tar.gz`
- `SHA256SUMS`
- `SBOM.spdx.json`
- `release-contents.json`

On a compatible Linux x86-64 system:

```bash
sha256sum --check SHA256SUMS
tar -xzf vulnimprint-linux-x86_64.tar.gz
./vulnimprint/bin/vulnimprint version
./vulnimprint/bin/vulnimprint scan --json ./vulnimprint/bin/vulnimprint-scan
```

The final command scans the native executable included in the archive, so no
separate test file is required. Replace its path with your own ELF binary or
use `--recursive` to scan a directory. Findings are returned as JSON.

The release includes the scanner and production CVE database. You do not need
Python, Rust, a Factory installation or a separate YARA-X runtime to scan.
The archive is built on Ubuntu 24.04 and requires a compatible Linux runtime,
including glibc and OpenSSL. For provenance and SBOM checks, see
[Release verification](docs/RELEASE_SIGNING.md).

## Current support

| Component | Supported |
|---|---|
| OS and binary format | Linux ELF (`ET_REL`, `ET_EXEC`, `ET_DYN`) |
| CPU and bitness | Little-endian x86-64, 64-bit |
| ABI | System V AMD64 |
| Scanner | C++20, ELFIO and YARA-X 1.23.0 C API |
| Reports | JSON with CVE, record, pattern and file offsets |
| Signature corpus | Five libpng CVEs, 25 machine-code patterns |

The [CVE catalog](docs/DATABASE.md#current-source-catalog) lists the bundled
coverage. The libpng research includes **36 expected pattern observations**
across real library specimens and **no unexpected matches on 230 unrelated
ELF files**; methods and specimen details are in the
[research report](docs/research/libpng-elf64-x86_64/README.md).
CVE records are maintained independently, so contributors can add patterns
for new vulnerabilities or different compiled variants of an existing CVE.

## Next steps

The immediate priority is to grow the production signature corpus toward
**100 CVEs**, improve coverage across compilers and builds, and collect
feedback from people scanning real binaries.

The source tree also includes the shorter `vulnip` launcher for upcoming
release packages; `vulnimprint` remains the standard command.

The [roadmap](docs/ROADMAP.md) covers the longer-term goal of 1,000 CVEs and
additional platforms: Windows/PE, macOS/Mach-O, Linux ELF32, ARM/AArch64 and
other ABIs and executable formats. Contributions to these areas are welcome
without delaying work on the current CVE corpus.

## Contribute

**Know a CVE we should detect?** [Propose a signature or report a missing
match](https://github.com/Andrew-Job/vuln_imprint/issues/new?template=cve_signature.yml).
A CVE identifier, public reference or reproducible binary test is enough to
start a discussion; a finished signature is not required.

You can also submit machine-code rules, test existing detections on your own
binaries, improve Scanner or Factory, or work on a new platform. Start with
[Contributing](CONTRIBUTING.md), the
[signature source tree](signatures/README.md), or the
[open issues](https://github.com/Andrew-Job/vuln_imprint/issues).
Pull requests are reviewed by the maintainer.

## Under the hood

The Scanner is written in C++20 and uses the official YARA-X C API for
matching. The Python Signature Factory supports compiler-aware research,
disassembly, pattern generation and validation. CVE-owned records live in Git
and are assembled into the database distributed with each release.

See [Architecture](docs/ARCHITECTURE.md), [Database](docs/DATABASE.md) and
[Development](docs/DEVELOPMENT.md) for implementation details and source-build
instructions.

VulnImprint is licensed under MIT. See [Security](SECURITY.md),
[Dependencies](docs/DEPENDENCIES.md) and
[Third-party notices](THIRD_PARTY_NOTICE.md).
