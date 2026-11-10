# CVE signature source tree

Each `signatures/CVE-YYYY-NNNN/` directory represents one CVE:

- `research.json` records a CVE investigation without a machine signature.
- `pack.json` and `rules-exec.yar` define the CVE's database records and YARA-X rules.

A CVE may own multiple records. Each record has a stable `record_id`, one
platform profile, one channel (`test` or `production`), and one or more machine
patterns. Records belong to exactly one CVE, even when patterns are identical.

| Channel | Test database | Production database |
|---|---|---|
| `test` | Included | Excluded |
| `production` | Included | Included |

The channel selects which database includes a record. Detection quality and
supported binary variants are documented in the corresponding evidence under
[`docs/research/`](../docs/research/).

For the record format and database assembly, see [Database](../docs/DATABASE.md).
For creating signatures, see the [CVE guide](../docs/CREATING_AND_VALIDATING_CVE_MASKS.md).
