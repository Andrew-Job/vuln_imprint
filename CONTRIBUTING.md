# Contributing

Contributions are reviewed through GitHub pull requests. Use a branch or
fork and keep changes scoped. Run `make format`, `make test`, and, for native
changes, the pinned native integration suite. CI validates functional
contracts and full-source formatting; missing integration dependencies fail
rather than skip tests. Do not commit secrets or unlicensed specimen binaries.

For a CVE proposal, prepare experimental rules outside the production
`signatures/validated/` tree. Manual rules can start with
`python -m tools.manual_rules init`, but format lint is **not** vulnerability
validation. Document real affected, fixed, backported and unrelated specimens,
source and patch-state evidence, binary SHA-256, and the complete measured
compiler profile where known. Independent native YARA-X validation is required.

Only the three canonical approved files under
`signatures/validated/CVE-.../` are merged after technical review. The
reviewed corpus is an independently hosted validation input, pinned by SHA
in `release/reviewed-corpus.lock.json` and restricted to the hostname
configured by repository maintainers. It must agree byte-for-byte with
source files in Git; it does not supply production rules. Every admitted CVE
enters the next release automatically, without a second selection step.
Changing a rule requires renewed validation and renewed evidence digests.

For security vulnerabilities affecting VulnImprint itself, use the private
reporting channel described in [SECURITY.md](SECURITY.md), not public issues.
