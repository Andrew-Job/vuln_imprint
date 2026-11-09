# Contributing to VulnImprint

Contributions include **new CVE signatures**, additional binary/build
variants, results from scanning real software, tooling improvements and
platform backends. You can open an issue with a CVE and public reference,
submit a machine-code rule or report a reproducible match. You do not need
to build the Scanner to propose a CVE. See the [roadmap](docs/ROADMAP.md)
for coverage goals and platform development directions.

## Ways to contribute

- **Grow the CVE corpus.** Propose an uncovered CVE, share a machine-code
  signature, or add implementation/compiler variants to an existing CVE.
  Include affected code, public references, disassembly or reproducible builds
  where available. A research-only issue is a useful starting point too.
- **Exercise real binaries.** Try a published Scanner package on software you
  are authorized to inspect. Report missed matches, unexpected matches or
  unclear diagnostics; provide a minimal reproducible case when possible.
- **Extend platform coverage.** Contribute new executable-format adapters,
  CPU architectures, ABIs and validation profiles. A new format or ABI needs
  coordinated changes across Scanner, Factory and database validation;
  changing record metadata alone does not enable it. See the
  [roadmap](docs/ROADMAP.md).
- **Improve implementation and documentation.** Propose focused changes to
  tests, packaging, Factory research or scanner behavior.

For initial ideas, open a
[GitHub issue](https://github.com/Andrew-Job/vuln_imprint/issues/new/choose).
For code and records, use a fork and pull request. Changes are reviewed by
the project maintainer before merging. CI results are available on PRs; the
maintainer makes the final merge decision.

## A useful CVE submission

Include what you can: the CVE identifier and references, affected component
and build, architecture/ABI, the suspicious machine-code sequence or proposed
rule, and how you checked it. Affected/fixed/backported builds and unrelated
binaries make a much stronger contribution when they can be shared or
reproduced lawfully. You may start with research or an issue rather than a
complete rule. Do not upload confidential, proprietary or unlicensed binaries.

### Source model

`signatures/CVE-YYYY-NNNN/` is the version-controlled CVE tree. A CVE may
own multiple DB records; each record has a globally unique, stable
`record_id` and belongs to exactly one CVE. If the same pattern is useful for
another CVE, duplicate it into a separate record belonging to that CVE.
This keeps independent CVE maintenance possible.

There are exactly two database inclusion channels:

| Channel | Test database | Published production database |
|---|---|---|
| `test` | Included | Excluded |
| `production` | Included | Included |

The channel determines packaging, not correctness or approval status.

### Create a machine-code record

Follow [Creating and validating CVE masks](docs/CREATING_AND_VALIDATING_CVE_MASKS.md)
for **prebuilt-binary or source-build routes** to select and validate a
security-specific machine pattern. Then add the validated bytes to the database.
For a manual machine-code record, use the mask prepared by the guide:

```bash
CVE=CVE-YYYY-NNNN
MASK="$(cat work/mask.hex)"
python -m tools.manual_rules init --cve "$CVE" \
  --record-key vulnerable-variant --channel test --hex "$MASK" \
  --output "signatures/$CVE"
python -m tools.manual_rules lint --directory "signatures/$CVE"
```

Use a distinct `--record-key` for additional independent records under one
CVE. New manual records default to `test`. The initializer generates a Linux
ELF64 x86-64 record using the native implementation's profile and writes
schema-3 `pack.json` and canonical `rules-exec.yar` together. Commit both,
and include evidence or reproduction instructions supporting the detection.

Source validation and native YARA-X compilation are required. CVE-specific
quality is assessed using relevant affected, fixed, backport and unrelated
controls when available; see [Database](docs/DATABASE.md) for evidence schema
and review commands.

## Verify your change

Run relevant formatting and first-party tests before submitting a PR:

```bash
make format-check
make test
```

For Scanner, Factory/YARA-X integration and CVE DB changes, run the native
suite in the [documented build environment](docs/DEVELOPMENT.md):

```bash
make test-native
```

If you cannot execute the native build, state the limitation in your PR;
do not report unexecuted tests as passing. Do not commit secrets, generated
release archives, or third-party specimen binaries.

For vulnerabilities **in VulnImprint itself**, use private vulnerability
reporting as described in [Security](SECURITY.md), not a public issue.
