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
| Recorded mask-index observations | **36 / 36** |
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
