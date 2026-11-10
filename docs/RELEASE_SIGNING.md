# Verify a VulnImprint release

Download these assets from the same [GitHub Release](https://github.com/Andrew-Job/vuln_imprint/releases):

- `vulnimprint-linux-x86_64.tar.gz` — Scanner and production database
- `SHA256SUMS` — file checksums
- `SBOM.spdx.json` — software bill of materials
- `release-contents.json` — release composition

With [GitHub CLI](https://cli.github.com/) and `sha256sum` installed, run:

```bash
for asset in vulnimprint-linux-x86_64.tar.gz SHA256SUMS \
             SBOM.spdx.json release-contents.json; do
  gh attestation verify "$asset" --repo Andrew-Job/vuln_imprint \
    --signer-workflow Andrew-Job/vuln_imprint/.github/workflows/release.yml
done
sha256sum --check SHA256SUMS
tar -xzf vulnimprint-linux-x86_64.tar.gz
./vulnimprint/bin/vulnimprint version
```

Attestations identify the publishing repository and workflow. SHA-256 checks
verify the downloaded files; the installed launcher verifies the bundled
database before scanning.
