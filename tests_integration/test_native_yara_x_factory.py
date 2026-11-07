"""Mandatory integration with pinned, source-built YARA-X Python bindings.

Only the VulnImprint adapter contract is tested here. Missing YARA-X is a
failure, never an optional skip. The C++ adapter has its own native smoke.
"""

from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from factory import yara_engine
from factory.signature_identity import new_record_id

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

    cve = "CVE-2099-56789"
    record_id = new_record_id(cve)
    rules = yara_engine.source_from_packs([{
        "schema_version":
            3,
        "cve":
            cve,
        "records": [{
            "record_id": record_id,
            "channel": "test",
            "source_type": "factory",
            "platform": {
                "os": "linux",
                "format": "ELF",
                "arch": "x86-64",
                "bits": 64,
                "abi": "sysv",
            },
            "rules": [{
                "hex": MARKER.hex(" ")
            }],
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
        "cve": cve,
        "record_id": record_id,
        "pattern": "$v0",
        "file_offset": 117,
    }]
    negative = reloaded.scan(Path("fixed.elf"))
    assert negative["detected"] is False
    assert negative["matches"] == []


def test_pipeline_validate_yara_x_uses_real_binding_and_offsets(monkeypatch):
    """Exercise the Factory entry point with compiled YARA-X and file offsets."""
    try:
        import yara_x  # noqa: F401 - mandatory native integration dependency
    except ImportError as exc:
        pytest.fail(
            "Pinned YARA-X Python binding is missing. "
            "Run scripts/build_yarax_python.sh before native integration tests: "
            f"{exc}",
            pytrace=False,
        )

    from factory.patterns import Pattern
    from factory.pipeline import validate_yara_x

    marker = bytes(range(1, 33))
    pattern = Pattern(marker, b"\xff" * len(marker))
    ranges = {
        "affected.elf": [(113, b"PADDING" + marker + b"TAIL")],
        "fixed.elf": [(113, b"PADDING" + b"X" * len(marker) + b"TAIL")],
    }

    class SyntheticElf:

        def __init__(self, target):
            self.target = Path(target)

        def executable_ranges(self):
            return ranges[self.target.name]

    # Only ELF extraction is substituted; pattern compilation and matching
    # still execute the upstream YARA-X Python binding.
    monkeypatch.setitem(sys.modules, "factory.elf",
                        SimpleNamespace(ELF=SyntheticElf))
    samples = [
        SimpleNamespace(id=name, path=Path(name), regions=regions)
        for name, regions in ranges.items()
    ]
    assert validate_yara_x("CVE-2099-56789", [pattern], samples) == {
        "status": "PASS",
        "mismatches": [],
    }
