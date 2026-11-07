# VulnImprint Factory — compiler profiles

A **compiler family is not a compiler version**. Each compiler profile
records its family, version, executable identity and optimization explicitly.

## Default research build profiles

| Family | Explicit executable | Version lane | Optimizations |
|---|---|---|---|
| GCC | `gcc-11` | 11.x | `-O2`, `-O3` |
| GCC | `gcc-12` | 12.x | `-O2`, `-O3` |
| Clang | `clang-14` | 14.x | `-O2`, `-O3` |
| Clang | `clang-15` | 15.x | `-O2`, `-O3` |

These eight compiler/optimization lanes are built as **affected and fixed**:
16 build jobs and 48 experimental specimen entries per CVE in generated
fork-local research recipes. These specimens are *not* blinded independent holdouts.

The catalog declares `profile.compiler`, `compiler_major`,
`compiler_executable` and `optimization`. The build script verifies the
actual installed compiler, records its **full detected version**, target
triplet, executable real path, SHA-256 of the compiler executable and the exact
optimization. `toolchain-provenance.json` is copied into CAS and the Factory
report. A mismatching version or missing report is fatal, never silently
replaced by the runner's default `cc` or `clang`.

A pinned **major lane** does not by itself guarantee byte-identical builds
across runner updates. For repeatability, freeze exact patch version using
`profile.compiler_version_exact`, the exact binary SHA-256 and a controlled
container image/toolchain package snapshot. Compiler identification is not a
claim of CVE-specific validation.

## Release evidence and DB index

Reviewed independent holdouts use `reviewed-evidence.json` schema version 3
with a source-built sample's `build_profile`:

```json
{
  "compiler_family": "gcc",
  "compiler_major": 12,
  "compiler_version": "12.3.0",
  "compiler_binary_sha256": "<64 lowercase hex characters from the measured executable>",
  "compiler_target": "x86_64-linux-gnu",
  "optimization": "-O2"
}
```

The validator requires actual version+binary digest for source-built affected,
fixed and backport controls. Independently obtained stripped third-party
products may legitimately have an unidentified compiler; do not infer a
version for them, and do not count them toward compiler coverage. An independent affected and fixed control is mandatory for **each lane
claimed by a CVE** in its `supported_profiles`. The eight-lane experimental
matrix is a source of coverage hypotheses, not a universal claim for every
rule. The published
`index.json` records the **observed** full compiler versions under each CVE's
`tested_build_profiles`; it does not imply the rule works on other compiler
versions, ABI, flags, LTO modes or operating systems.

Optional command to inspect locally available research compiler profiles:

```bash
python -m tools.check_toolchain_matrix --out toolchain-matrix.json
```

No rule may claim cross-compiler or cross-version support merely because
fields for them exist in the schema. The supported target remains Linux
ELF64 little-endian x86-64 SysV. Generate and run source-build experiments in a contributor fork or
working directory. Factory-generated records default to the `test` channel.
A contributor can explicitly assign a record to `production`; this is a
channel-selection decision, not a validation-state promotion. Detection
correctness is assessed separately.

## Additional compiler profiles

The default Factory research recipes target GCC 11/12 and Clang 14/15,
when those compilers are installed. Native CI does not install these
research-only compiler lanes; it tests the product with the build compiler
and the pinned YARA-X engine. Research profiles may specify other compilers:

```bash
python scripts/create_catalog.py --records /tmp/research-cve-records.json \
  --output-dir /tmp/vulnimprint-modern-catalog \
  --compiler-lanes gcc-15 gcc-16 clang-22 clang-23
```

This creates build recipes. It does not establish that the toolchains are
installed or that any CVE is detectable under those profiles.
