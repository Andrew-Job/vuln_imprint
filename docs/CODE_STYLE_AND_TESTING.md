# Source style and meaningful testing

## Language standards

This repository uses established, upstream conventions instead of a
VulnImprint-specific coding style:

- **C++20:** [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html),
  with `clang-format` using the upstream `Google` preset and only the four-space indentation override. The checked-in
  `.clang-format` is the sole C++ formatting configuration.
- **Python:** [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html),
  with YAPF's upstream `google` preset (`.style.yapf`). Python uses four-space
  indentation; C++ also uses four spaces. Do not apply these settings to external
  Git submodules or generated databases.
- **Shell/YAML:** ordinary ShellCheck and standard YAML syntax; no custom
  style implementation.

The Makefile invokes the formatter command-line tools directly: `clang-format`
for C++ and `yapf` for Python. It does not invoke YAPF through `python -m`.
On macOS, install both commands with Homebrew (`brew install clang-format
yapf`). CI installs the formatter packages from `requirements-format.txt` and
runs the same CLI commands. Keep `requirements-format.txt` separate
from `requirements-dev.txt`; formatting tools are not runtime or test
requirements. Use `make format` to format first-party source and
`make format-check` to inspect format differences. Formatting changes must
preserve behavior and be reviewed separately from semantic changes. Do not
reformat vendored or generated upstream code.

## Library-first implementation policy

Prefer maintained, well-defined APIs from the supported platform, Python
standard library, and pinned upstream dependencies. Before implementing a
format parser, instruction decoder, cryptographic primitive, compression
format, package metadata formatter or GitHub protocol by hand, check whether
an existing library or official API provides the required operation.

Local code is justified for **VulnImprint-specific policy** (which ELF regions
are scanned, CVE-specific affected/fixed decisions, release admission), for
strict resource limits around existing archive APIs, and for small glue that
cannot reasonably be replaced. Avoid implementations that duplicate general
library functionality. For instance, use `hashlib.file_digest` for file
hashes and the official YARA-X APIs for rule compilation and scanning.

## Library-first implementation

- `factory/elf.py` uses pinned **pyelftools 0.33** for ELF64 sections,
  executable segments, symbol bounds and relocation records. Invalid/unsupported
  ELF inputs fail closed. The C++ scanner uses a small ELFIO adapter for
  executable-range policy; it does not duplicate ELF structural parsing.
- `factory/disasm.py` uses pinned **Capstone 5.0.9** decoder detail. Only x86
  displacement and immediate fields whose byte offsets are reported by the
  decoder, plus known ELF relocation widths, are masked. Unknown relocation
  layouts are rejected, not guessed from disassembly strings.
- `tools/create_sbom.py` invokes pinned **Syft 1.57.0** on the *final product
  archive*. It validates the SPDX document schema and rejects failed or empty
  output. A build-time-only tool is preferred to a custom SPDX generator.
- Compiler provenance is captured from actual build invocations, exact compiler
  versions and SHA-256 output artifacts. Factory rejects source/toolchain/output
  drift before accepting versioned build profiles.

GitHub native CI installs dependencies and tests the integration boundaries
with pinned YARA-X and independent affected/fixed corpora.

## Test scope

Tests cover **VulnImprint-owned contracts**: ELF range selection, byte-pattern
normalization, extraction, provenance locking, reviewed evidence admission,
compiler lane recording, rule aggregation, compiled database integrity, embedded
release content integrity and user-facing launcher behavior.

Test doubles may stand in for an external tool **only to exercise our boundary**
(e.g. malformed C++ scanner JSON). They are not evidence that YARA-X, GCC,
Clang, GitHub or other dependencies work correctly. No tests should duplicate
third-party tool suites or depend on an unrelated package being present on the
runner. One native end-to-end integration smoke test with the pinned YARA-X is
required to verify **our adapter**; its absence is a release blocker.

Use pytest for deterministic unit/integration tests, with temporary fixture
files and explicit positive/negative outcomes. Prefer tests tied to a real bug
or documented contract over broad tests of constants, filenames, source text,
or arbitrary numerical milestones.

## Coverage and acceptance

Measure *branch* and line coverage of first-party Python modules with
`coverage.py`. C++ has separate compiler and native integration
coverage; do not add C++/Python lines into one misleading percentage.

Use `make test-coverage` to produce a text and JSON report. CI records coverage diagnostics without treating an arbitrary percentage
as evidence of detection correctness; full native CI runs both the C++ and
Python adapters with pinned YARA-X. No test in either suite may be skipped:
pytest fails the session on a skipped result. Coverage
is a **diagnostic**, not a proxy for correctness: reject
releases when crucial integration or CVE evidence checks have not passed,
regardless of percentage. New code must include behavior-based tests for
failure modes and public behavior, without creating meaningless test volume.

CI checks the complete first-party source tree, including on pushes to `main`.

See [Release contract](RELEASE_CONTRACT.md) for release acceptance gates.
Only tests executed for the exact source revision establish its CI status.
