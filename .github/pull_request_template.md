## Change summary

Which CVE or first-party component changes, and why?

## CVE admission (for rules under `signatures/validated/`)

- [ ] Exact `pack.json`, `rules-exec.yar` and `reviewed-evidence.json` are included
- [ ] Reviewed independent affected/fixed/backport and unrelated sample corpus is pinned
- [ ] All claimed GCC/Clang version/optimization lanes are independently checked
- [ ] Native CI verifies **all** Git CVEs against the matching reviewed corpus
- [ ] Unapproved rules are excluded from `signatures/validated/`; specimen binaries are excluded from Git

## First-party checks

- [ ] Offline test and quality checks
- [ ] Native YARA-X adapter / integration checks
- [ ] Licensing, provenance and documentation checked

All merged CVEs enter the next release automatically. A PR never edits a
per-release CVE selection file.
