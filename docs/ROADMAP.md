# VulnImprint roadmap

**Primary priority: expand machine-code signature coverage to 100 CVEs, then
1,000 CVEs.** New operating systems, executable formats, architectures and
ABIs are also important and open to community contributions. They can be
developed in parallel; they are not prerequisites for growing the CVE corpus
on the existing platform.

The milestones below are community goals, not release deadlines. A GitHub
release is a separately chosen product snapshot; merging a CVE pull request
does not automatically publish a new version.

## 1. CVE corpus: 100 → 1,000

| Milestone | Scope |
|---|---|
| **Current corpus** | Five CVEs represented by production machine-code records (25 patterns); one additional research-only CVE |
| **First goal: 100 CVEs** | Grow the production corpus to 100 distinct CVEs with machine-code detection records |
| **Next goal: 1,000 CVEs** | Continue expanding the production corpus across components and reproducible build variants |
| **Ongoing work** | Add alternative patterns, test affected/fixed builds, review coverage gaps and maintain existing CVEs |

**We count distinct CVEs, not patterns or records.** A CVE can own multiple
independent records and each record can carry multiple machine-code patterns.
A byte sequence useful for two CVEs belongs to separately maintained records
under those CVEs. `test` and `production` are database inclusion channels, not
confidence levels; the milestones above measure CVEs represented in the
published `production` channel.

High-value contributions include:

- New CVE records for the current platform, backed by public references and
  reproducible or lawfully shareable observations.
- Alternative signatures covering different compilers, optimizations,
  patches, backports, and other compiled variants of an existing CVE.
- Reproducible affected/fixed comparisons and reports of missed or unexpected
  matches in binaries that contributors are authorized to analyze.
- Research cases and issue reports where a complete signature is not yet
  available. These can guide subsequent CVE-record contributions.

See [Contributing](../CONTRIBUTING.md), the
[signature source tree](../signatures/README.md), and
[Database](DATABASE.md) for the CVE-record model and evidence requirements.

## 2. Platform and architecture expansion

VulnImprint is designed to support multiple operating systems, binary formats,
CPU architectures, word sizes and ABIs. The current Scanner implements
Linux ELF64, little-endian x86-64, System V AMD64 ABI; the matching database
and Factory target this profile.

| Direction | Opportunities for contributors |
|---|---|
| **Linux 32-bit** | ELF32 executable-range handling, x86 and other 32-bit ABIs, fixtures and tests |
| **Windows** | PE32/PE32+, x86/x64, Windows ABI profiles, executable ranges, packaging and tests |
| **macOS** | Mach-O, arm64/x86-64, macOS ABIs, executable regions, packaging and tests |
| **Additional CPUs** | ARM, AArch64, other ISAs and endianness, disassembly and signature validation |
| **More binary environments** | Other executable formats, ABIs, runtime and toolchain profiles |

These are **development directions**, while current runtime support is
summarized in the README. The order depends on useful proposals and available
implementations, not on a fixed platform-by-platform release schedule.

### A practical route to a new target

1. Define its OS, binary format, CPU architecture, word size and ABI profile.
2. Implement executable-range parsing and correct original file offsets in
   the Scanner; extend Factory research paths for the relevant instruction set
   and toolchains.
3. Extend validation and database assembly for that platform profile, while
   retaining CVE-owned records and the existing `test`/`production` channels.
4. Add representative product-level tests, sample binaries that can be
   redistributed or reproduced, and documentation for the runtime/package.

Adding metadata alone does not enable a new platform, but a contributor does
not need to implement every layer alone: start with a focused proposal and
coordinate changes through [Issues](https://github.com/Andrew-Job/vuln_imprint/issues/new/choose).

## 3. Detection quality, tooling and distribution

Work on the corpus and platform backends benefits from parallel improvements
in signature research, compiler/build coverage, test specimen reproducibility,
false-positive/false-negative investigation, scan performance and packaging.
The Signature Factory and native Scanner should make it easier to contribute
and exercise new CVE records without adding unnecessary complexity to the
database model or the release workflow.

## How to take part

**Want to help now?** The fastest path is to propose a CVE or submit a
machine-code signature for the current Linux target. Try the published release on
binaries you can inspect and report missing coverage. For Windows, macOS,
ELF32, ARM or another backend, open a platform proposal with a first testable
slice. Code, machine-code records, tests, and documentation are all welcome
through forks and pull requests.

The maintainer reviews and merges contributions. For technical architecture,
see [Architecture](ARCHITECTURE.md); for CVE source structure, see
[Contributing](../CONTRIBUTING.md).

