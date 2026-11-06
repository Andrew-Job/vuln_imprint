"""Mandatory integration with pinned, source-built YARA-X Python bindings.

Only the VulnImprint adapter contract is tested here. Missing YARA-X is a
failure, never an optional skip. The C++ adapter has its own native smoke.
"""

from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from factory import yara_engine

MARKER = bytes.fromhex("48 83 EC 28 48 8B 05 12 34 56 78 48 85 C0")


def test_factory_compiles_saves_loads_and_scans_executable_offsets(
        tmp_path, monkeypatch):
    try:
        import yara_x  # noqa: F401 - fail if the required binding was not built
    except ImportError as exc:
        pytest.fail(
            "Pinned YARA-X Python binding is missing. "
            "Run scripts/build_yarax_python.sh before native integration tests: "
            f"{exc}",
            pytrace=False,
        )

    rules = yara_engine.source_from_packs([{
        "cve": "CVE-2099-56789",
        "status": "RESEARCH_ONLY",
        "platform": {
            "format": "ELF"
        },
        "rules": [{
            "hex": MARKER.hex(" ")
        }],
    }])
    compiled = yara_engine.YaraXScanner.compile(rules)
    database = tmp_path / "database.yarc"
    compiled.save(database)
    assert database.stat().st_size > 0
    reloaded = yara_engine.YaraXScanner.load(database)

    class SyntheticElf:

        def __init__(self, target: Path):
            self.target = target

        def executable_ranges(self):
            if self.target.name == "affected.elf":
                return [(111, b"prefix" + MARKER + b"suffix")]
            if self.target.name == "fixed.elf":
                return [(111, b"prefix" + b"X" * len(MARKER) + b"suffix")]
            raise AssertionError("Unexpected specimen")

    monkeypatch.setitem(sys.modules, "factory.elf",
                        SimpleNamespace(ELF=SyntheticElf))
    positive = reloaded.scan(Path("affected.elf"))
    assert positive["detected"] is True
    assert positive["matches"] == [{
        "rule": "CVE_2099_56789_ELF64_x86_64",
        "pattern": "$v0",
        "file_offset": 117,
    }]
    negative = reloaded.scan(Path("fixed.elf"))
    assert negative["detected"] is False
    assert negative["matches"] == []
