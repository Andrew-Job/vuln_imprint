# Non-production CVE research

`libpng-elf64-x86_64/` contains five machine-code CVE rule candidates and 25
hex masks. They are tracked as a research reference,
**not** marked `CVE_SPECIFIC_VALIDATED` and **not** included by the
production database builder, which reads `signatures/validated` only.

Run `python -m scripts.check_candidate_sources` to verify these sources and
machine-code anchors. To run reference matching when the exact 9 libpng
specimens and 230 SHA-256-pinned unrelated ELF samples are available, run
`python signatures/candidates/libpng-elf64-x86_64/scripts/replay_offline.py
--project-root .` from the repo root. This replay is not YARA-X compilation,
nor evidence of independent GCC/Clang/patch-state controls.

Promotion into `signatures/validated` requires separate reviewed affected,
fixed, backport and unrelated corpora, checked provenance, native YARA-X,
and final combined-regression acceptance. No bypass is provided.
