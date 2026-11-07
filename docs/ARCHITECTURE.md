# Architecture

VulnImprint is a static, CVE-oriented Linux ELF machine-code scanner. Its
supported binary target is little-endian ELF64 x86-64, System V ABI.
The execution engine is official YARA-X 1.23.0 (C API); ELF metadata is
parsed by ELFIO 3.12. Scanner execution does not execute or emulate the target.

```text
Factory (Python): source provenance, builds, disassembly, pattern validation
      |
      v
signatures/CVE-*/: research.json and optional independent DB records
      |
      v
Git source checks -> YARA-X test database -> native integration checks
      |
      v
production_db assemble (production records only)
      |
      v
Native Scanner (C++20, static YARA-X C API) + compiled DB + metadata
      |
      v
verified release archive and separately attested release assets
```

## Executable-range policy

- `ET_REL`: bytes of sections with `SHF_EXECINSTR`.
- `ET_EXEC` and `ET_DYN`: file-backed intersections of `SHF_EXECINSTR`
  sections and `PT_LOAD` segments marked `PF_X`, including partial overlaps.
- `ET_EXEC` and `ET_DYN` without section headers: the file-backed ranges of
  executable `PT_LOAD` segments. These ranges can also contain non-code bytes.

Offsets refer to the original file. Virtual addresses are reported only when
unambiguously mapped; an `ET_REL` file offset is not a linked virtual address.
The scanner rejects unsupported or malformed ELF with diagnostics. Diagnostic
`--all-sections` scans the full **validated ELF**, not arbitrary files, and
classifies findings according to their executable-range membership.

The JSON schema is `vulnimprint.scan.yarax.v2`. Every machine-rule finding
identifies its CVE, independent `record_id`, pattern and file offset. The
reported `cve_count` counts unique CVEs, not patterns or records. Linux
pathname bytes are preserved in `file_bytes_hex`, while `file` is for display.
Errors and truncated results are explicit.

## Records, evidence and release

A CVE may own zero or more records, each with a canonical `record_sha256`,
platform profile, alternative machine patterns and channel `test` or
`production`. Reusing the same bytes for another CVE requires a separately
owned record. Channel selection controls database inclusion, **not**
detection confidence.

Factory records compiler/source provenance and checks proposed patterns with
the pinned Python YARA-X binding. `production_db review` validates independently
collected per-record evidence; it does not generate a database.
`production_db assemble` is the only builder of the compiled test and
production databases, taking records from the Git source tree.

The release ships the Native Scanner statically linked with YARA-X and the
compiled production database together. Build/test jobs and publication jobs
have separate privileges; publication verifies the complete artifact set.
See [Database](DATABASE.md), [Development](DEVELOPMENT.md) and
[Release verification](RELEASE_SIGNING.md).

A machine-code match is evidence of bytes matching a specific rule, not proof
of exploitability. A clean scan cannot rule out a CVE or an unexamined build
profile.
