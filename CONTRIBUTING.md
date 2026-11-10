# Contributing to VulnImprint

Contributions include **new CVE signatures**, additional binary/build
variants, results from scanning real software, tooling improvements and
platform backends. You can open an issue with a CVE and public reference,
submit a machine-code rule or report a reproducible match. You do not need
to build the Scanner to propose a CVE. See [Architecture](docs/ARCHITECTURE.md)
for supported targets and [Database](docs/DATABASE.md) for signature records.

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
  changing record metadata alone does not enable it. See
  [Architecture](docs/ARCHITECTURE.md).
- **Improve implementation and documentation.** Propose focused changes to
  tests, packaging, Factory research or scanner behavior.

For initial ideas, open a
[GitHub issue](https://github.com/Andrew-Job/vuln_imprint/issues/new/choose).
For code and records, use a fork and pull request. Changes are reviewed by
the project maintainer before merging. CI results are available on PRs; the
maintainer makes the final merge decision.

Create a separate branch for each change:

```bash
git switch -c feature/describe-change
# Make your changes.
git add -A
git commit -m "Describe the change"
git push -u origin HEAD
```

Open a pull request against `main`. GitHub Actions runs the project checks.
Release builds are started separately after the pull request is merged.

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

### Add a machine-code record

Follow [Creating and validating CVE masks](docs/CREATING_AND_VALIDATING_CVE_MASKS.md).
Submit the CVE-owned `pack.json`, `rules-exec.yar` and sample evidence in your
pull request. GitHub Actions runs the project checks on the PR; the maintainer
reviews the results before merging.

For vulnerabilities **in VulnImprint itself**, use private vulnerability
reporting as described in [Security](SECURITY.md), not a public issue.
