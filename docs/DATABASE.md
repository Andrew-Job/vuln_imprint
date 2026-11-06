# CVE signature source and compiled database

`signatures/validated/CVE-YYYY-NNNN/` contains the three reviewed source files
`pack.json`, `rules-exec.yar` and `reviewed-evidence.json`. Only entries in
this directory are compiled for production. `signatures/candidates/` contains
unapproved research and is never a database input. Multiple machine patterns
for one CVE are alternatives, not multiple independent vulnerabilities.

`tools.production_db build` is the **admission** validator and needs the
independent specimen corpus and real native scanner. `tools.production_db
assemble` is the **release** compiler: it consumes the entire Git-validated
source tree after technical admission and builds one `.yarc` with the pinned
native YARA-X C API. It has no per-CVE selection argument.

The compiled output contains:

```text
database.yar         combined reviewed YARA source
database.yarc        compiled native YARA-X rules
index.json           unique CVE IDs, pattern counts and evidence profiles
quality-report.json  reviewed-source metadata; not a fresh CVE validation
manifest.json        digests and pinned engine compatibility
SHA256SUMS           checksums of the database payload
```

The index records observed compiler identity where it is included in the
reviewed evidence. It is not a claim of universal compiler coverage.

These files are included directly under
`vulnimprint/share/vulnimprint/db/` in the **one** public application archive.
The installed launcher checks the four payload files listed in the bundled
`SHA256SUMS` (`database.yar`, `database.yarc`, `index.json`, and
`quality-report.json`) before every scan. The `manifest.json` and database
checksum list are covered by verification of the release archive before
installation, not by this launcher check. Updating the application means
downloading and verifying a new complete release. There is no
standalone database archive, updater, or version-store selection path.

New formats and architectures will require corresponding binary loaders,
versioned database profiles, runtime integration tests and independent CVE
validation. A change to profile support must not silently broaden the
existing Linux ELF64 x86-64 claim.
