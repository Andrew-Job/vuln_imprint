# Security policy

VulnImprint processes untrusted executable files, source archives and CVE
research inputs. Use appropriately isolated runners for experiments and do
not feed unreviewed build commands to a privileged workstation or CI runner.
The Factory does not sandbox external build recipes.

## Private vulnerability reports

For security vulnerabilities in VulnImprint, use GitHub's private
vulnerability reporting on the repository's **Security** tab. Do not post
unpatched exploits, private specimens or credentials in public issues.
Provide the affected commit/version, reproduction and impact if possible.
No response-time SLA is promised.

A CVE detector itself must pass independent native affected/fixed/backport
and unrelated checks before admission. Published assets must be verified via
GitHub artifact attestations and SHA-256 checks before loading the database.
