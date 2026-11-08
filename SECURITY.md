# Security policy

VulnImprint processes untrusted executable files, source archives and CVE
research inputs. Use appropriately isolated runners for experiments and do
not feed unreviewed build commands to a privileged workstation or CI runner.
The Factory does not sandbox external build recipes.

## Private vulnerability reports

For security vulnerabilities **in VulnImprint itself**, use private
vulnerability reporting under the repository's **Security** tab when enabled.
If private reporting is unavailable, open a non-sensitive issue to request a
secure reporting channel; do not disclose exploit details there. Do not
post credentials, private specimens or unpatched exploits in public issues.
Include the affected release/commit, reproduction and impact when possible.

CVE signature proposals, missed detections and unexpected matches belong in
regular Issues or pull requests rather than private product vulnerability
reports. Supporting affected/fixed, backport and unrelated build controls
are valuable for assessing CVE detection quality; see
[Contributing](CONTRIBUTING.md) and [Database](docs/DATABASE.md).

Verify published assets with GitHub Artifact Attestations and SHA-256 checks
before loading the database.
