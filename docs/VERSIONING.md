# Release versioning

VulnImprint uses `MAJOR.MINOR.PATTERNS` rather than Semantic Versioning.

- **MAJOR** is set in `tools/release_version.py` and changed through a pull request.
- **MINOR** is the next number after the highest published GitHub Release with
  that MAJOR. A new MAJOR starts at MINOR 1.
- **PATTERNS** is the number of machine patterns in the assembled production
  database, including alternative patterns but excluding the `test` channel.

To publish, merge a pull request into `main`, then run **Actions → VulnImprint
verified release → Run workflow** on `main`. GitHub Actions builds the product,
calculates the version and publishes the Git tag and Release.
