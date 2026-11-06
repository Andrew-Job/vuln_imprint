# Architecture

```text
Factory research (Python) -> candidate YARA-X rules and evidence
           |
           v
independent native CVE validation + technical PR review
           |
           v
signatures/validated/ (Git: single approved CVE source of truth)
           |
           v
native YARA-X compilation of all approved rules at release build
           |
           v
one installable application archive: scanner + runtime + DB
           |
           v
verified GitHub Release with attestation and integrity manifests
```

## Scanner

The C++20 scanner reads regular files without following symlinks, validates
the currently supported ELF64 little-endian x86-64 format through ELFIO,
selects file-backed executable regions, scans through the official YARA-X
C API, and emits structured matching offsets, CVE IDs, truncation and errors.
`--all-sections` is a diagnostic full-file scan of an **already validated ELF**,
not an arbitrary-file scanner. The code and rule-validation profiles must be
extended together before accepting other formats or architectures.

## Factory and database

Factory orchestrates pinned source acquisition, versioned build profiles,
disassembly and candidate masks. Candidate masks are never automatically
production rules. CVE approval includes independent affected/fixed/backport
and unrelated controls, source/digest provenance, and native YARA-X validation.
Approved `pack.json`, `rules-exec.yar` and `reviewed-evidence.json` files are
tracked under `signatures/validated/` in the protected Git tree.

A separate corpus of independent specimen binaries exists only for native
admission tests. It is never consumed by the user's launcher. The release
build uses the complete approved source tree and publishes one compatible
compiled database within the application archive; the installed version
and DB are upgraded together.

## Compatibility boundary

Only the first Linux ELF64 x86-64 profile is implemented and tested.
Additional formats (PE, Mach-O, firmware images), architectures, ABIs and
compiler variants are future profile implementations, not present claims.
Unsupported file formats produce explicit errors rather than clean results.
