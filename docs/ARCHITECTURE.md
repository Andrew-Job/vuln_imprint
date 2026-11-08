# Architecture

VulnImprint is an extensible, static, CVE-oriented binary signature scanner.
Its platform model identifies the operating system, executable format,
CPU architecture, bitness and ABI separately. Scanner backends and signature
profiles are implemented against those dimensions. Matching uses the
YARA-X C API; executable-format adapters locate the bytes to be scanned
and translate findings to original file offsets. Scanning does not execute
or emulate the target.

```text
Factory (Python): source provenance, builds, disassembly, pattern validation
      |
      v
signatures/CVE-*/: research.json or pack.json + rules-exec.yar
      |
      v
Git source checks -> YARA-X test database -> native integration checks
      |
      v
production_db assemble (production records only)
      |
      v
Native Scanner (C++20, YARA-X C API) + compiled DB + metadata
      |
      v
verified release archive and separately attested release assets
```

## Platform model and backend contracts

Every CVE-owned record carries `platform.os`, `platform.format`,
`platform.arch`, `platform.bits` and `platform.abi`. Compiler/build profiles
and signature alternatives express additional coverage dimensions. A
platform profile is valid for scanning when the corresponding format and
architecture support is implemented and validated across the Scanner,
Factory and database tooling. Adding metadata alone does not add executable
format support.

Each backend must correctly select executable ranges, preserve original file
offsets, handle malformed inputs, validate compatible signature profiles and
have representative native tests. See the [Platform roadmap](ROADMAP.md)
for contribution opportunities. Published release assets specify the runtime
and target environments of the distributed packages.

## Executable-range policy: ELF backend

The ELF implementation uses ELFIO to parse executable metadata:

- `ET_REL`: bytes of sections with `SHF_EXECINSTR`.
- `ET_EXEC` and `ET_DYN`: file-backed intersections of `SHF_EXECINSTR`
  sections and `PT_LOAD` segments marked `PF_X`, including partial overlaps.
- `ET_EXEC` and `ET_DYN` without section headers: file-backed ranges of
  executable `PT_LOAD` segments. These ranges can also contain non-code bytes.

Offsets refer to the original file. Virtual addresses are reported only when
unambiguously mapped; an `ET_REL` file offset is not a linked virtual address.
The ELF backend reports malformed or unrecognized ELF inputs as diagnostics.
Diagnostic `--all-sections` scans the complete validated ELF, not arbitrary
files, and classifies findings by executable-range membership.

The JSON schema is `vulnimprint.scan.yarax.v2`. Every machine-rule finding
identifies its CVE, independent `record_id`, pattern and file offset. The
reported `cve_count` counts unique CVEs, not patterns or records. The ELF
implementation preserves Linux pathname bytes in `file_bytes_hex` alongside
the display-oriented `file` value. Errors and truncated results are explicit.

## CVE records, evidence and release assembly

A CVE may own zero or more independent records, each with a canonical
`record_sha256`, platform profile, alternative machine patterns and channel
`test` or `production`. Reusing the same bytes for another CVE requires a
separately owned record. Channel selection determines database inclusion,
**not** detection confidence.

Factory records source/compiler provenance and checks proposed patterns
against YARA-X. `production_db review` validates independently collected
per-record evidence; it does not generate a database. `production_db assemble`
is the release database builder and reads records from the Git source tree.
Factory research snapshots are experimental artifacts, not distributable
production databases.

Each release couples the native Scanner and a compiled production database.
Build/test jobs and publication jobs have separate privileges; release
publication verifies the complete artifact set. See [Database](DATABASE.md),
[Development](DEVELOPMENT.md) and [Release verification](RELEASE_SIGNING.md).

A machine-code match is evidence that bytes match a particular detection rule;
it is not, by itself, proof of exploitability. A clean scan does not establish
the absence of all CVEs or all compiled variants.
