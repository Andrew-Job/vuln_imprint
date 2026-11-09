# Pre-alpha 0.1.1: real-ELF CVE signature cases

The release source tree adds **ten CVE records and 19 YARA-X-compatible hexadecimal patterns**.
The first two were part of the preceding pre-alpha patch; eight were added by this extension.

Each pattern was screened against SHA-256-pinned real executable ELF segments,
with observed file offsets; controls were selected by patch-state disassembly,
not solely by version strings. These reports are **PASS_PRELIMINARY**.
Native YARA-X compilation, Scanner tests and independent reviewed evidence
are not recorded as completed. Inclusion channel `production` does not change
this evidence status.

| CVE | Library | Patched function/operation | Patterns | Affected / fixed / unrelated | Upstream/security source |
|---|---|---|---:|---:|---|
| CVE-2025-64505 | libpng | `png_set_quantize / quantize_index` | 4 | 5/3/232 | [source](https://www.cve.org/CVERecord?id=CVE-2025-64505) |
| CVE-2025-64506 | libpng | `png_image_write_main` / `png_write_image_8bit` | 3 | 5/3/232 | [source](https://www.cve.org/CVERecord?id=CVE-2025-64506) |
| CVE-2019-7317 | libpng | `png_image_free` | 2 | 3/4/232 | [source](https://libpng.org/pub/png/libpng.html) |
| CVE-2023-52356 | libtiff | `TIFFReadRGBATileExt` | 2 | 2/3/232 | [source](https://access.redhat.com/security/cve/cve-2023-52356) |
| CVE-2024-7006 | libtiff | `_TIFFFindOrRegisterField` | 1 | 1/2/232 | [source](https://git.enea.com/cgit/linux/poky.git/diff/?id=c048a86145567a371e309bc4977fdd2a1c753a6f) |
| CVE-2025-9900 | libtiff | `TIFFReadRGBAImageOriented` | 3 | 3/2/232 | [source](https://security-tracker.debian.org/tracker/CVE-2025-9900) |
| CVE-2026-24515 | libexpat | `XML_ExternalEntityParserCreate` | 1 | 1/1/232 | [source](https://github.com/libexpat/libexpat/pull/1131) |
| CVE-2026-50219 | libexpat | `XML_Parse` | 1 | 1/1/232 | [source](https://github.com/libexpat/libexpat/pull/1246) |
| CVE-2026-56131 | libexpat | `XML_ResumeParser` | 1 | 1/1/232 | [source](https://github.com/libexpat/libexpat/pull/1267) |
| CVE-2026-56406 | libexpat | `XML_ParseBuffer` | 1 | 1/1/232 | [source](https://github.com/libexpat/libexpat/pull/1255) |

## Reproduce a result

For the eight newly added cases, each `CVE-ID.samples.json` records control
origin, exact SHA-256, expected patch state and local path used in the run.
The adjacent `evidence/CVE-ID.reference.json` stores every observed match offset.
Sample paths identify the original on-disk installations and must be mapped
to your local copies with **matching hashes** before reproducing the run.

```bash
CVE=CVE-2026-56406
python -m tools.binary_samples --cve "$CVE" \
  --pack "signatures/$CVE/pack.json" \
  --samples "docs/research/binary-first-0.1.1/$CVE.samples.json" \
  --output "work/$CVE.replay.json"
python -m tools.manual_rules lint --directory "signatures/$CVE"
```

The original [libpng research dossier](../libpng-elf64-x86_64/README.md)
contains the two 2025 CVE matrices and the baseline libpng source investigation.

## Why the bytes represent the vulnerable code

- **CVE-2019-7317:** `png_image_free` uses the old `png_safe_execute`
  cleanup path, removed in the 1.6.37 correction.
- **CVE-2023-52356:** `TIFFReadRGBATileExt` enters tile row/column
  arithmetic without the patched post-initialization bounds checks.
- **CVE-2024-7006:** `_TIFFFindOrRegisterField` passes the anonymous field
  allocation result to `_TIFFMergeFields` without the added null guard.
- **CVE-2025-9900:** `TIFFReadRGBAImageOriented` computes the raster pointer
  from an unvalidated image-height subtraction (patched 4.7.1 path differs).
- **CVE-2026-24515:** `XML_ExternalEntityParserCreate` copies handler state
  but omits the unknown-encoding handler data. In fixed Expat 2.8.3 it
  loads parent `+0x1f0` and stores child `+0x1f0`.
- **CVE-2026-50219:** `XML_Parse` reaches parsing-state processing without
  the new handler-depth check at fixed VMA `0xa400`.
- **CVE-2026-56131:** `XML_ResumeParser` continues from stopped status
  without the new handler-depth check at fixed VMA `0xa635`.
- **CVE-2026-56406:** `XML_ParseBuffer` updates the cursor by unchecked
  pointer addition at affected VMA `0x9102`; fixed code branches on carry.

All VMAs are specific to the SHA-pinned specimen and are **not** encoded
as universal file locations in the signature.
