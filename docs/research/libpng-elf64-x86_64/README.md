# Libpng ELF64 x86-64 machine-code signature research

**Five production CVE records, 25 machine-code patterns.** This research
records matches and control observations on real libpng binaries; see the
measurements and specimen inventory below.

## Delivery

- Five libpng CVE-owned DB records, **25 YARA-X-compatible hex patterns** (`database-exec.yar` here and individual `signatures/CVE-*/rules-exec.yar`). Source assembled by existing `factory.yara_engine.source_from_packs` from versioned CVE `pack.json` manifests; the project manual source validator checks each case.
- **CVE-2026-33416** with 10 patterns covering the observed `png_set_PLTE` and `png_set_tRNS` pointer-alias variants; **CVE-2026-34757** with 5 patterns covering the observed `png_set_hIST` free-before-copy variant. The 15 corresponding machine-code anchors are recorded in `machine-anchors.json`, with binary SHA-256, file offset, disassembly, fixed-byte count and semantic explanation.
- **CVE-2026-22695**, **CVE-2026-22801**, and **CVE-2026-25646**: 3 rules and 10 patterns.
- One additional prepared libpng case, **CVE-2026-46675**, is included in the research dossier but **not** emitted as a machine rule without a fixed machine-code control (upstream fix changes `pngrutil.c`).

## Results actually obtained

| Control | Result |
|---|---:|
| CVEs with YARA source | 5 |
| Machine patterns | 25 |
| Actual libpng shared libraries | 9 |
| Recorded mask-index observations | **45 / 45** |
| Unrelated real ELF files | **230** |
| Unexpected unrelated matches | **0** |
| Matches for CVE-2026-33416 and CVE-2026-34757 | All hits inside expected named functions |
| YARA-X executed in the recorded source research | **No** |
| Eight-lane independent GCC/Clang source builds | **No** |

The seven affected-path specimens are not independently source-proven rebuilds. Two distinct negative controls have machine code with the relevant fixed behavior: a Debian 1.6.48 security-backport library and a bundled libpng 1.6.58 library. Hashes are preserved in `evidence/specimen-inventory.json`; provenance limitations remain. Negative observations are **not** proof of no false positives in other builds. No binary is distributed here; third-party binaries are identified by SHA-256 and local paths.

### Source-level review rationale

**CVE-2026-33416:** upstream changed PLTE and tRNS buffer ownership to remove aliasing of one allocation across `png_struct` and `png_info`. Vulnerable PLTE bodies store one allocation result into both structures; fixed PLTE bodies allocate separate objects. Vulnerable tRNS bodies transfer the pointer from `info_ptr->trans_alpha` to `png_ptr->trans_alpha`; patched cases do not. Confirmed upstream references: [Debian CVE tracker](https://security-tracker.debian.org/tracker/CVE-2026-33416), [upstream tRNS fix](https://github.com/pnggroup/libpng/commit/23019269764e35ed8458e517f1897bd3c54820eb).

**CVE-2026-34757:** before the fix `png_set_hIST` can free the stored buffer before reading from a caller-supplied pointer which aliases it. In the patched control, a stack-backed copy is made first. The markers capture specific vulnerable compiled paths, not arbitrary calls to `png_free_data`. Source: [upstream advisory](https://www.openwall.com/lists/oss-security/2026/04/09/2), [Debian CVE tracker](https://security-tracker.debian.org/tracker/CVE-2026-34757).

**CVE-2026-46675:** the 1.6.59 patch introduces `png_inflate_detach_buffers` and calls it at stream-release points. A patch must be contrasted with actual fixed/unfixed executable paths: absent instructions cannot themselves be a positive YARA signature. No synthetic signature was invented for this CVE. [Upstream fix](https://github.com/pnggroup/libpng/commit/aa77ef38c17ab2fc1b41bec09fb973c6a386641d).

## Binary-first CVE screening replay

The existing **CVE-2026-33416** record was replayed directly against
SHA-pinned, real prebuilt ELF libraries (no source recompilation). The
preliminary reference matcher confirmed **7/7 affected-path matches**, **2/2
fixed-path non-matches** and **24/24 unrelated ELF non-matches**; 17 concrete
file-offset hits were recorded. Inputs and results:

- [`binary-first-CVE-2026-33416.samples.json`](binary-first-CVE-2026-33416.samples.json)
- [`evidence/binary-first-CVE-2026-33416.reference.json`](evidence/binary-first-CVE-2026-33416.reference.json)

A narrower demonstration extracts a single security-relevant `png_set_PLTE`
mask from the RDKit binary, checks it against one affected, one patched and
one unrelated ELF, and creates a schema-3 CVE-owned **test** record using
`tools.manual_rules init`. Its control matrix and report are
[`binary-first-CVE-2026-33416.single-mask.samples.json`](binary-first-CVE-2026-33416.single-mask.samples.json)
and [`evidence/binary-first-CVE-2026-33416.single-mask.reference.json`](evidence/binary-first-CVE-2026-33416.single-mask.reference.json).
This single-mask record is a reproducible authoring demonstration and is
**not** committed as a duplicate of the existing production record.

Run the full example from the project root:

```bash
python -m tools.binary_samples --cve CVE-2026-33416 \
  --pack signatures/CVE-2026-33416/pack.json \
  --samples docs/research/libpng-elf64-x86_64/binary-first-CVE-2026-33416.samples.json \
  --output work/CVE-2026-33416-reference.json
```

This is only reference byte matching over executable ELF segments. The
sample paths point to specific SHA-256-pinned third-party installations; the
upstream binary producer and complete source lineage were not independently
attested. Neither YARA-X nor native Scanner was executed in this new replay.
For end-to-end source-to-production admission, follow
[Creating and validating CVE masks](../../CREATING_AND_VALIDATING_CVE_MASKS.md).

## Two additional CVE records: real prebuilt binaries (2025)

The original five-CVE research corpus above is unchanged. Two **new**, separately
maintained production-channel records were added using the binary-first path
in [the contributor guide](../../CREATING_AND_VALIDATING_CVE_MASKS.md):

| CVE | Vulnerable code | Fix | Patterns | Affected / fixed / backport / unrelated |
|---|---|---|---:|---:|
| [CVE-2025-64505](https://www.cve.org/CVERecord?id=CVE-2025-64505) | `png_set_quantize` allocates `quantize_index` using `num_palette` | Allocate 256 bytes to cover the full 8-bit palette-index space | 4 | 5 / 2 / 1 / 232 |
| [CVE-2025-64506](https://www.cve.org/CVERecord?id=CVE-2025-64506) | `png_image_write_main` condition routes 8-bit input into the 16-bit conversion path | Correct the combined `linear`, `alpha` and `convert_to_8bit` guard | 3 | 5 / 2 / 1 / 232 |

Both vulnerabilities were fixed in **libpng 1.6.51**, released on
**2025-11-21**. Their upstream fixing commits are
[`6a528eb5fd0dd7f6de1c39d30de0e41473431c37`](https://github.com/pnggroup/libpng/commit/6a528eb5fd0dd7f6de1c39d30de0e41473431c37)
(64505) and
[`2bd84c019c300b78e811743fbcddb67c9d9bf821`](https://github.com/pnggroup/libpng/commit/2bd84c019c300b78e811743fbcddb67c9d9bf821)
(64506). Compare the exact affected instruction blocks with these fixes
before editing the masks.

**Inputs.** Five affected bundled-libpng ELF builds were taken from
`rdkit==2025.9.4`, `pedalboard==0.9.23`, `fiona==1.10.1`,
`cadquery-ocp==7.9.3.1.1` and `torchvision==0.25.0+cpu`.
The fixed builds came from `pillow==12.3.0` and
`opencv-python==4.13.0.92`. A Debian `libpng16-16t64` security-backport
build was tested separately. There were also **232 unrelated real ELF
controls**. The manifests pin **SHA-256 for every file** and document
each sample's source and classification. These are diverse package builds,
not proven independent compiler/source reproduction lineages.

**Replay the committed masks** after obtaining the exact binaries from the
indicated packages and updating local paths in a private copy of each
sample manifest (without modifying the pinned SHA-256):

```bash
python -m tools.binary_samples --cve CVE-2025-64505 \
  --pack signatures/CVE-2025-64505/pack.json \
  --samples docs/research/libpng-elf64-x86_64/binary-first-CVE-2025-64505.extended.samples.json \
  --output work/CVE-2025-64505.json

python -m tools.binary_samples --cve CVE-2025-64506 \
  --pack signatures/CVE-2025-64506/pack.json \
  --samples docs/research/libpng-elf64-x86_64/binary-first-CVE-2025-64506.extended.samples.json \
  --output work/CVE-2025-64506.json
```

The frozen reference results are
[`CVE-2025-64505`](evidence/CVE-2025-64505.extended.source-pack.json)
and
[`CVE-2025-64506`](evidence/CVE-2025-64506.extended.source-pack.json).
Both returned **PASS_PRELIMINARY** on all 240 pinned ELF files. For the first
record, the five affected-library hit file offsets are
`83194, 83232, 99170, 82700, 85509`; for the second, they are
`145967, 146047, 200925, 147826, 158972`, ordered as the sample matrices.

**Pre-alpha acceptance status.** Both records have `channel=production` for
release inclusion. Their evidence reports explicitly set
`native_yara_x_executed=false` and `production_admission=false`: the test
above is direct byte matching inside executable `PT_LOAD` ranges, not a
YARA-X runtime or native Scanner validation. Do not interpret channel
selection as a reviewed accuracy claim. Before a verified release, run
`tools.production_db review/assemble/verify` and the native Scanner across
the same controls using the instructions in [Database](../../DATABASE.md).

## Reproduction

Requires the current VulnImprint source tree on `PYTHONPATH`, GNU binutils and the original local ELF files identified by SHA-256. Example:

```bash
python docs/research/libpng-elf64-x86_64/scripts/check_source_only.py --project-root .
python docs/research/libpng-elf64-x86_64/scripts/replay_offline.py --project-root .
```

The source check validates the five rule sources, 25 patterns and 15 recorded machine-code anchors. The offline replay **fails closed** if the exact source specimens are unavailable; with them it validates the 36 expected observations plus 230 unrelated files. Replay results are written to standard output; expected observations are recorded in `validation-matrix.json`. GNU `readelf` supplies executable segments.

## Confidence boundary

- Hex tokens are limited to whole bytes and `??` wildcards, which are supported by [the official YARA-X hex-pattern grammar](https://virustotal.github.io/yara-x/docs/writing_rules/hex-patterns/). Rule structure is generated from project-owned source code, not freeform text. **This does not replace running the actual YARA-X compiler.**
- The five CVE packs each own their machine records. The `production` channel means the records are included in the current production DB; it is not a correctness or validation claim.
- CVE-2026-34757 signatures cover the affected `hIST` variant; the transient PLTE/tRNS regression specifically in libpng 1.6.56 is not covered by these masks.
- CVE-2026-33416 coverage is bounded to the observed PLTE/tRNS implementations. Unknown compiler and optimization combinations remain untested.
- Research queue entries without source and bytecode evidence are **not** database rules. The remaining prepared libpng CVE and the generic wider queue require separate evidence collection.

## Additional locality verification

```bash
python docs/research/libpng-elf64-x86_64/scripts/check_cve_locality.py --project-root .
```

This checks all new signatures over entire raw specimen files and demands that
**every** observed match fall entirely inside the expected exported function in
an executable `PT_LOAD`. It also enforces positive and fixed-control results
and prints the result to standard output. It does not verify complete CVE semantics,
source-lineage independence or official YARA-X runtime compatibility.

The recorded patterns cover the observed compiled libpng implementations.
Further compiler, optimization and backport variants can extend that coverage;
the observed results and methods are preserved above for reproducibility.
