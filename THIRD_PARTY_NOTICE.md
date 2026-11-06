# Third-party notices

VulnImprint's original source files are available under the repository's MIT license. Dependencies are independently licensed:

| Dependency | Purpose | Source | License | Distribution |
|---|---|---|---|---|
| YARA-X 1.23.0 (`yara-x-capi`) | Official matching engine | https://github.com/VirusTotal/yara-x | BSD-3-Clause | Pinned Git submodule `external/yara-x`. Release bundles include its native shared library; preserve the upstream license and copyright notice in binary distributions. |
| ELFIO Release 3.12 | ELF structural parser in the C++ scanner | https://github.com/serge1/ELFIO | MIT | Pinned Git submodule `external/elfio`; header-only code is compiled into the scanner, and the upstream `LICENSE.txt` is included in the product archive. |
| pyelftools 0.33 | Structured ELF parsing in Signature Factory | https://github.com/eliben/pyelftools | Public domain | Exact PyPI version in requirements-factory.txt; installed for research/CI, not bundled in scanner. |
| Capstone 5.0.9 | x86-64 instruction decoding in Signature Factory | https://github.com/capstone-engine/capstone | BSD-3-Clause | Exact PyPI version; installed for research/CI, not bundled in scanner. |
| Syft 1.57.0 | SBOM of the finalized release product | https://github.com/anchore/syft | Apache-2.0 | Build-time tool only, immutable GitHub release and asset attestation verified; not bundled in product. |
| zlib | Optional Factory affected/fixed source corpus | https://github.com/madler/zlib | zlib license | Acquired by individually locked Git commits, not bundled in the release repository. |
| libpng | Optional Factory affected/fixed source corpus | https://github.com/pnggroup/libpng | libpng license | Acquired by individually locked Git commits, not bundled in the release repository. |

The upstream YARA-X repository can include other dependencies governed by its Cargo.lock and their own licensing notices. The release process must audit the dependency license set and distribute the required notices along with the shared library. A release **must not** include third-party affected/fixed binaries unless their redistribution rights have been reviewed.

This document is attribution information, not a replacement for the original third-party license texts.
