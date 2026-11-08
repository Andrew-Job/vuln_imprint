# CVE source records and compiled database

## Source model

`signatures/CVE-YYYY-NNNN.../` is the sole authoring tree. Each CVE can have
`research.json` without a machine record, or a schema-version-3 `pack.json`
containing one or more independent DB records. `rules-exec.yar` is the
canonical YARA-X source derived from the pack. One record belongs to exactly
one CVE; patterns shared with another CVE are duplicated in a separate record.

```json
{
  "schema_version": 3,
  "cve": "CVE-2026-12345",
  "records": [
    {
      "record_id": "VI_0123456789ABCDEF01234567",
      "channel": "test",
      "source_type": "manual",
      "platform": {
        "os": "linux", "format": "ELF", "arch": "x86-64",
        "bits": 64, "abi": "sysv"
      },
      "rules": [{
        "id": "CVE-2026-12345-pattern-0",
        "hex": "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90",
        "length": 28,
        "fixed_bytes": 28
      }]
    }
  ]
}
```

The example bytes are synthetic, **not** a CVE detector. Each `record_id`
is globally unique, stable and deterministic. Its `record_sha256` covers the
canonical content of that record independently of siblings in the same CVE.
Each pattern has validated syntax, length and fixed-byte metadata.

There are exactly two inclusion channels:

| Channel | Test database | Production database |
|---|---|---|
| `test` | included | excluded |
| `production` | included | included |

Channel assignment makes no claim about accuracy, exploitability, compiler
coverage or the absence of false positives. New manual records default to
`test`. A research-only CVE creates no machine rules.

## Current source catalog

| CVE | Records | Patterns |
|---|---:|---:|
| `CVE-2026-22695` | 1 | 1 |
| `CVE-2026-22801` | 1 | 4 |
| `CVE-2026-25646` | 1 | 5 |
| `CVE-2026-33416` | 1 | 10 |
| `CVE-2026-34757` | 1 | 5 |
| `CVE-2026-46675` (research only) | 0 | 0 |
| **Total: 6 CVEs** | **5** | **25** |

All five machine records have the `production` inclusion channel. Research
artifacts and machine anchors are available in
`docs/research/libpng-elf64-x86_64/`. A separate per-record independent
affected/fixed/backport validation remains a research goal; inclusion in the
production database is not a statement that this review is complete.

## Platform profiles and future coverage

`platform` has five explicit dimensions: `os`, `format`, `arch`, `bits` and
`abi`. These fields make coverage identifiable per CVE record and provide
a consistent basis for future Windows PE, macOS Mach-O, Linux ELF32 and
other format/ABI contributions. The current assembler validates the one
implemented Linux ELF64 x86-64 SysV profile. Extending the accepted profile
set requires coordinated Scanner, Factory, source validation and native
integration changes; a JSON metadata edit alone is insufficient.

See [Platform roadmap](ROADMAP.md).

## Review and assembly

Reviewed evidence schema 3 binds the exact `record_id` and `record_sha256`,
explicit `sample_ids`, training lineages and controls for each record. A
sibling record's finding does not satisfy a positive or negative control.
The reviewer evaluates affected, fixed, backport and unrelated examples
within each claimed compiler profile. Existing production records without
reviewed evidence remain selectable for assembly; acceptance of newly changed
records is separately reviewed.

```bash
python -m tools.production_db review --cases CASES \
  --scanner build/scanner/vulnimprint-scan --signatures signatures

python -m tools.production_db assemble --signatures signatures \
  --channel test --output build/db-test \
  --scanner build/scanner/vulnimprint-scan
python -m tools.production_db verify --database build/db-test \
  --scanner build/scanner/vulnimprint-scan

python -m tools.production_db assemble --signatures signatures \
  --channel production --output build/db-production \
  --scanner build/scanner/vulnimprint-scan
python -m tools.production_db verify --database build/db-production \
  --scanner build/scanner/vulnimprint-scan
```

`review` validates independent evidence without generating a database.
`assemble` is the only release-database builder: it reads Git-tracked
source and compiles with native YARA-X. Factory may create temporary
research snapshots with `factory.database.merge_packs`; these are not
release databases and cannot replace `assemble` artifacts. `verify` checks the built artifacts. Source structure and
successful compilation alone do not validate CVE semantics.

The database format version is **1**; `pack.json` schema version is **3**.
Database artifacts are:

| Artifact | Purpose |
|---|---|
| `database.yar` | Canonical YARA-X source |
| `database.yarc` | Serialized native YARA-X rules |
| `index.json` | CVEs, channels, record IDs/hashes and separate counts |
| `database-report.json` | Database composition summary |
| `manifest.json` | Engine compatibility and artifact digests |
| `SHA256SUMS` | Database payload checksums |

A match identifies its CVE, `record_id`, pattern and file offset; `cve_count`
is the number of unique CVEs with findings. The release ships a consistent
scanner and database under `vulnimprint/share/vulnimprint/db/`, verified by
the installed launcher. There is no separately supported database updater.

## Manual authoring

```bash
python -m tools.manual_rules init \
  --cve CVE-2026-12345 --record-key variant-a --channel test \
  --hex 'AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66 77 88 99 00 11' \
  --output run/cve-proposals/CVE-2026-12345
python -m tools.manual_rules lint \
  --directory run/cve-proposals/CVE-2026-12345
```

Use a separate stable `--record-key` for each independent record within a
CVE. The initializer generates `pack.json` and `rules-exec.yar` together.
Source lint and real YARA-X compilation are mandatory; they do not assert
that synthetic or newly authored bytes detect a vulnerability.
