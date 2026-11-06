# Verify a published VulnImprint release

The publisher signs complete release artifacts using GitHub Artifact
Attestations (Sigstore/OIDC). YARA-X itself does not sign `.yar` or `.yarc`
files; a compiled database is not authenticated without the release trust
chain. Git-reviewed source integrity and release signing are distinct.

The supported distribution is **one application archive** accompanied by
`SBOM.spdx.json`, `release-contents.json` and `SHA256SUMS`. The production
archive contains all Git-tracked records assigned to the `production` channel.
Records assigned to `test` are excluded. Each DB record belongs to exactly
one CVE; records with identical patterns under different CVEs remain separate
and independently identified. The inclusion channel does not assert
detection correctness.

## Consumer verification

Download all four assets from the same published release, then verify the
actual tag and publisher repository. The tag below is an example only;
substitute the tag of the release being installed.

```bash
for asset in vulnimprint-linux-x86_64.tar.gz \
             release-contents.json SBOM.spdx.json SHA256SUMS; do
  gh attestation verify "$asset" \
    --repo Andrew-Job/vuln_imprint \
    --source-ref refs/tags/v0.1.0 \
    --signer-workflow Andrew-Job/vuln_imprint/.github/workflows/release.yml
done

gh attestation verify vulnimprint-linux-x86_64.tar.gz \
  --repo Andrew-Job/vuln_imprint \
  --source-ref refs/tags/v0.1.0 \
  --predicate-type https://spdx.dev/Document/v2.3 \
  --signer-workflow Andrew-Job/vuln_imprint/.github/workflows/release.yml

sha256sum --check SHA256SUMS
tar -xzf vulnimprint-linux-x86_64.tar.gz
./vulnimprint/bin/vulnimprint version
```

The commands assume `gh`, GNU `sha256sum` and `tar` are installed on the
verifying system. A hash alone is not proof of publisher identity; never
skip the attestation check. For maximum assurance, also compare release
asset digests obtained from GitHub with the downloaded bytes and verify the
published release's immutability using `gh release verify`.

The installed launcher performs local SHA-256 checks before invoking the
native scanner. Installing a new verified complete release is the supported
upgrade path. Trust in the signer is not a substitute for independently
validated CVE detection.
