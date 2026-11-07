# Contributing

Contributions use GitHub pull requests and protected CI. Work in a fork or
branch. Run `make format`, `make test`, and the native suite for changes to the
scanner, CVE records, Factory, or release tooling. Tests must not skip required
integrations. Do not commit secrets or third-party specimen binaries.

## CVE records and database channels

`signatures/CVE-YYYY-NNNN/` is the single version-controlled CVE tree. CVE is
the authoring and maintenance unit. A CVE may own multiple database records;
each record has a globally unique `record_id` and belongs to exactly one CVE.
A record never lists multiple CVEs. If a pattern applies to another CVE, copy
it into a separate record under that CVE. The duplication is intentional and
allows independent edits and lifecycle management.

Each record uses one of two channels:

- `test`: included in the test database only.
- `production`: included in both test and production databases.

New manual records default to `test`:

```bash
python -m tools.manual_rules init \
  --cve CVE-2022-37434 \
  --record-key alternate-implementation \
  --channel test \
  --hex 'AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66 77 88 99 00 11' \
  --output run/cve-proposals/CVE-2022-37434
```

The `record-key` is stable and distinguishes multiple records for one CVE.
The generated `pack.json` schema version 3 and canonical `rules-exec.yar` must
be committed together. `rules-exec.yar` contains one YARA rule per DB record,
with one CVE in its metadata.

The channel is a database inclusion target, not a correctness grade. A
production assignment does not prove that a detector is accurate or that the
named vulnerability is exploitable. Source validation and native compilation
are mandatory CI checks; CVE-specific detection correctness is investigated
separately. The release builder includes every structurally valid production
record and does not perform quality-status promotion.

For VulnImprint security reports, use the private reporting channel in
[SECURITY.md](SECURITY.md).
