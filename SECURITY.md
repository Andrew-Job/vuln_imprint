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

New or changed CVE detection claims require independent affected, fixed,
backport and unrelated controls bound to the exact record and compiler
profiles. A production inclusion channel is not evidence of accuracy: the
production-channel records in this source tree have no independently
reviewed evidence of CVE detection accuracy.
Verify published assets with GitHub artifact attestations and SHA-256 checks
before loading the database.
