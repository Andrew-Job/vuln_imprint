## Change summary

Describe the affected first-party component or CVE and explain the change.

## CVE source changes (when changing `signatures/`)

- [ ] Each DB record belongs to exactly one CVE
- [ ] Every `record_id` is stable and globally unique
- [ ] Every record uses only the `test` or `production` channel
- [ ] Reused byte patterns have separate CVE-owned records
- [ ] `pack.json` and `rules-exec.yar` are consistent
- [ ] Pattern bytes, lengths and fixed-byte counts are correct
- [ ] Research-only CVEs retain `research.json` when no machine record exists
- [ ] Native YARA-X test database compilation and verification pass
- [ ] No third-party specimen binaries, generated releases or secrets in Git

## Verification

- [ ] Source formatting and meaningful first-party tests pass
- [ ] Native adapter tests pass when affected
- [ ] Documentation, provenance and license impact reviewed

The Git CVE tree is the source of truth. Production release assembly includes only `production` records; CI test assembly includes both channels.
