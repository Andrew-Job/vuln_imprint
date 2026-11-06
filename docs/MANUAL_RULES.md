# Manual YARA-X CVE rule authoring

A CVE rule can originate from a researcher instead of the automated Factory. Manual input is a first-class **source** route; it is not an exception to evidence or release admission.

## Create an independent rule

Use the restricted pilot hex syntax (fixed two-nibble bytes, wildcard `??`, without includes/imports):

```bash
python -m tools.manual_rules init \
  --cve CVE-2022-37434 --hex 'AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66 77 88 99 00 11' \
  --output run/cve-proposals/CVE-2022-37434
python -m tools.manual_rules lint --directory run/cve-proposals/CVE-2022-37434
```

The shown bytes are **synthetic, not a verified CVE detector**. The initializer generates `pack.json` (`source_type: manual`, `status: CANDIDATE_ONLY`) and `rules-exec.yar`. The reviewer must ensure the actual YARA source contains a single uniquely named rule, matching CVE metadata and exactly the approved bytes.

## Promotion

1. Document the advisory and exact source revisions proving affected and fixed patch states; pin sample SHA-256.
2. Validate independent affected, fixed, same-version patched/backport and unrelated specimens; record compiler family **and exact version**, optimization and compiler SHA-256 when known.
3. Obtain independent technical approval in a protected GitHub pull request,
   prepare `reviewed-evidence.json` as specified in `RELEASE_CONTRACT.md`, and
   commit the evidence bound to the exact rule/pack SHA-256. Per-CVE signing is
   not required; the release as a whole receives a publisher attestation.
4. Change the pack and YARA metadata to `CVE_SPECIFIC_VALIDATED` **only after** these checks, regenerate the two SHA-256 evidence references and move the reviewed source to `signatures/validated/CVE-...` in Git.
5. Required protected CI runs native independent-specimen validation against the entire Git-approved source tree before accepting a change. The release compiles and verifies exactly those approved Git rules without a separate corpus selection step.

The production source tree can contain **multiple independent CVEs**, each with multiple alternative hex patterns. The release concatenates source into one `database.yar`, compiles one `database.yarc`, and publishes one DB per platform profile. Neither a `CANDIDATE_ONLY` rule nor a version-only fingerprint qualifies for the main DB.
