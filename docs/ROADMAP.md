# VulnImprint roadmap

**Primary priority: grow the CVE machine-code signature corpus toward 100,
then 1,000 distinct CVEs.** Development of executable-format adapters,
platform backends, architecture profiles and tooling can proceed in parallel.
These are community development goals, not release dates. Published releases
remain separately verified snapshots of the product.

## 1. CVE signature coverage

| Milestone | Scope |
|---|---|
| **100 CVEs** | Expand the production signature database to 100 distinct CVEs |
| **1,000 CVEs** | Extend CVE coverage across components, implementations and reproducible build variants |
| **Continuous improvement** | Add alternative patterns, compare affected and fixed builds, review unexpected matches and maintain existing signatures |

**Coverage is counted by distinct CVEs, not records or patterns.** A CVE can
have multiple independently maintained records, and each record can contain
alternative machine-code patterns. The same bytes, when relevant to different
CVEs, belong to separate records. `test` and `production` determine database
inclusion, not confidence levels. Milestones count CVEs represented in the
published `production` database.

Useful contributions include new CVE records, alternative signatures for
compiler and optimization variants, reproducible affected/fixed comparisons,
and reports of missed or unexpected matches in binaries contributors are
authorized to inspect. Research proposals without a completed signature are
also welcome.

See [Contributing](../CONTRIBUTING.md), the
[signature source tree](../signatures/README.md) and
[Database](DATABASE.md).

## 2. Platforms, executable formats and architectures

VulnImprint's platform model separates operating system, executable format,
CPU architecture, word size and ABI. New backends and signature profiles can
be introduced independently of CVE corpus growth, provided the relevant
Scanner, Factory, database validation and tests evolve together.

| Direction | Contribution areas |
|---|---|
| **Linux** | ELF formats, 32-bit and 64-bit profiles, executable-range parsing and ABIs |
| **Windows** | PE32/PE32+, x86/x64, ABI profiles, executable ranges and packaging |
| **macOS** | Mach-O, arm64/x86-64, ABI profiles, executable regions and packaging |
| **Additional CPUs** | ARM, AArch64, other ISAs and endianness, disassembly and signature validation |
| **Additional environments** | Other binary formats, runtime environments, toolchains and ABI profiles |

These are development directions, not a statement that every listed target is
already implemented. For runnable packages and target requirements, refer to
the published [releases](https://github.com/Andrew-Job/vuln_imprint/releases).

### Adding a target profile

1. Define its OS, binary format, CPU architecture, word size and ABI.
2. Implement executable-range parsing and original file-offset semantics in
   the Scanner; extend Factory research for the relevant ISA and toolchains.
3. Extend source validation and database assembly for the profile, retaining
   CVE-owned records and the `test`/`production` inclusion channels.
4. Add representative native tests, reproducible samples and release-package
   documentation.

Metadata alone does not enable a new backend. Start with a focused
[issue](https://github.com/Andrew-Job/vuln_imprint/issues/new/choose)
and coordinate work across components.

## 3. Detection quality and tooling

Keep improving reproducible signature research, compiler/build coverage,
affected/fixed and unrelated test controls, false-positive and false-negative
investigation, scan performance, diagnostics and packaging. The Signature
Factory and native Scanner should make it practical to contribute and test
new CVE records while retaining a simple CVE-owned source model.

## How to take part

Propose a CVE, submit a machine-code signature, test a published package on
binaries you are authorized to inspect, or contribute a new backend and its
tests. Code, records, research cases and documentation are welcome through
forks and pull requests. The maintainer reviews and merges contributions.

For implementation details, see [Architecture](ARCHITECTURE.md) and
[Contributing](../CONTRIBUTING.md).
