# Contributing to VulnImprint

The most useful contributions right now are **new CVE signatures**,
additional binary/build variants and results from scanning real software.
You can open an issue with a CVE and public reference, submit a machine-code
rule or report a reproducible match. You do not need to build the Scanner to
propose a CVE. Work on Windows, macOS, Linux ELF32 and other architectures or
ABIs is also welcome; see the [roadmap](docs/ROADMAP.md) for platform
opportunities and longer-term CVE coverage milestones.

## Ways to contribute

- **Grow the CVE corpus.** Propose an uncovered CVE, share a machine-code
  signature, or add implementation/compiler variants to an existing CVE.
  Include affected code, public references, disassembly or reproducible builds
  where available. A research-only issue is a useful starting point too.
- **Exercise real binaries.** Try the published Scanner on software you are
  authorized to inspect. Report missed matches, unexpected matches or
  unclear diagnostics; provide a minimal reproducible case when possible.
- **Extend platform coverage.** Windows PE, macOS Mach-O, Linux ELF32,
  additional architectures and ABIs are welcome areas for development. See
  the [roadmap](docs/ROADMAP.md). A new format or ABI needs changes
  across the relevant scanner, Factory and database validation paths; merely
  changing record metadata does not enable it.
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

### Create a record for the current Linux target

For a manual machine-code rule, start with:

```bash
python -m tools.manual_rules init \
  --cve CVE-2022-37434 \
  --record-key alternate-implementation \
  --channel test \
  --hex 'AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66 77 88 99 00 11' \
  --output run/cve-proposals/CVE-2022-37434
```

The bytes are a **synthetic command example**, not a rule for that CVE.
Use a distinct `--record-key` for additional independent records under one
CVE. New manual records default to `test` and use the currently implemented
Linux ELF64 x86-64 platform. The initializer generates schema-3 `pack.json`
and canonical `rules-exec.yar` together. Commit both, and include evidence
or reproduction instructions that support the proposed detection.

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
