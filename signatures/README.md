# Published CVE source tree

Production CVE source-of-truth lives exclusively under
`validated/CVE-YYYY-NNNN/`, with `pack.json`, `rules-exec.yar`, and
`reviewed-evidence.json` for each reviewed CVE. All admitted CVEs enter every
non-empty production release automatically.

`candidates/libpng-elf64-x86_64/` contains non-production libpng research
rules and evidence. These files are **not** admitted to the release DB builder.
CVE submissions enter `validated/` only after independent review.

Sources are compiled into a single YARA-X DB per supported binary profile.
See `docs/DATABASE.md` and `CONTRIBUTING.md`.
