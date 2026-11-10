# libpng CVE signature evidence

Machine-pattern observations from real libpng ELF64 x86-64 libraries.
Each CVE has its own record and SHA-256-pinned evidence.

| CVE | Vulnerable operation | Patterns | Evidence |
|---|---|---:|---|
| CVE-2026-33416 | `png_set_PLTE` / `png_set_tRNS` pointer ownership | 10 | [`machine-anchors.json`](machine-anchors.json) |
| CVE-2026-34757 | `png_set_hIST` free-before-copy path | 5 | [`machine-anchors.json`](machine-anchors.json) |
| CVE-2026-22695 | libpng vulnerable implementation | 1 | [`validation-matrix.json`](validation-matrix.json) |
| CVE-2026-22801 | libpng vulnerable implementation | 4 | [`validation-matrix.json`](validation-matrix.json) |
| CVE-2026-25646 | libpng vulnerable implementation | 5 | [`validation-matrix.json`](validation-matrix.json) |
| CVE-2025-64505 | `png_set_quantize`: allocation sized by `num_palette` | 4 | [`samples`](binary-first-CVE-2025-64505.extended.samples.json) |
| CVE-2025-64506 | `png_image_write_main`: 8-bit/16-bit conversion condition | 3 | [`samples`](binary-first-CVE-2025-64506.extended.samples.json) |

## Patch references

- CVE-2026-33416: [upstream tRNS fix](https://github.com/pnggroup/libpng/commit/23019269764e35ed8458e517f1897bd3c54820eb) — corrects shared buffer ownership.
- CVE-2026-34757: [upstream advisory](https://www.openwall.com/lists/oss-security/2026/04/09/2) — corrects the `png_set_hIST` aliasing path.
- CVE-2025-64505: [upstream fix](https://github.com/pnggroup/libpng/commit/6a528eb5fd0dd7f6de1c39d30de0e41473431c37) — allocates the full palette-index range.
- CVE-2025-64506: [upstream fix](https://github.com/pnggroup/libpng/commit/2bd84c019c300b78e811743fbcddb67c9d9bf821) — corrects the 8-bit conversion guard.

The [specimen inventory](evidence/specimen-inventory.json) records sample
provenance and SHA-256; [machine anchors](machine-anchors.json) record
instruction-level explanations and original file offsets.

## Observations

The libpng reference specimens were screened against nine real libpng
libraries: 45/45 recorded mask observations matched expectations, with no
unexpected hit in 230 unrelated ELF controls. CVE-2026-33416 also has
[SHA-256-pinned affected/fixed samples](binary-first-CVE-2026-33416.samples.json)
and [observed file offsets](evidence/binary-first-CVE-2026-33416.reference.json).

For each of CVE-2025-64505 and CVE-2025-64506, the extended matrix contains
five affected, two fixed, one backported and 232 unrelated ELF files. These
samples returned `PASS_PRELIMINARY`; their SHA-256 and file offsets are in
[64505 evidence](evidence/CVE-2025-64505.extended.source-pack.json) and
[64506 evidence](evidence/CVE-2025-64506.extended.source-pack.json).

## Reproduce a matrix

With the SHA-identical ELF files available locally, update only sample paths
in a copy of the manifest and run:

```bash
python -m tools.binary_samples --cve CVE-2025-64505 \
  --pack signatures/CVE-2025-64505/pack.json \
  --samples docs/research/libpng-elf64-x86_64/binary-first-CVE-2025-64505.extended.samples.json \
  --output work/CVE-2025-64505.json
```

The observations are preliminary executable-byte screens for the recorded
build variants. Coverage depends on compiler and build configuration;
consult each sample matrix when interpreting a finding.
