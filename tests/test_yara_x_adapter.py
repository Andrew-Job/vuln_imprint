"""Unit tests for VulnImprint's Python scan adapter, not for YARA-X itself."""

from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from factory import yara_engine


def test_adapter_preserves_file_offsets_and_isolates_executable_ranges(
        monkeypatch):
    marker = b"VULNIMPRINT_MARKER"
    segments = [(500, b"unrelated"), (120, b"before" + marker + b"after")]
    scanned = []

    class ElfFixture:

        def __init__(self, target):
            assert target == Path("example.elf")

        def executable_ranges(self):
            return segments

    class ScannerFixture:

        def scan(self, data):
            scanned.append(data)
            if marker not in data:
                return SimpleNamespace(matching_rules=[])
            match = SimpleNamespace(offset=data.index(marker))
            pattern = SimpleNamespace(identifier="$marker", matches=[match])
            rule = SimpleNamespace(identifier="VI_1234567890ABCDEF12345678",
                                   metadata=(("cve", "CVE-2099-12345"),),
                                   patterns=[pattern])
            return SimpleNamespace(matching_rules=[rule])

    monkeypatch.setitem(sys.modules, "factory.elf",
                        SimpleNamespace(ELF=ElfFixture))
    scanner = yara_engine.YaraXScanner.__new__(yara_engine.YaraXScanner)
    scanner.scanner = ScannerFixture()
    report = scanner.scan(Path("example.elf"))

    assert scanned == [segment for _, segment in segments]
    assert report["engine"] == "YARA-X/executable-ELF"
    assert report["detected"] is True
    assert report["matches"] == [{
        "cve": "CVE-2099-12345",
        "record_id": "VI_1234567890ABCDEF12345678",
        "pattern": "$marker",
        "file_offset": 126
    }]


def test_adapter_reports_no_findings_for_unmatched_code(monkeypatch):

    class ElfFixture:

        def __init__(self, target):
            pass

        def executable_ranges(self):
            return [(0, b"no vulnerability here")]

    class ScannerFixture:

        def scan(self, data):
            return SimpleNamespace(matching_rules=[])

    monkeypatch.setitem(sys.modules, "factory.elf",
                        SimpleNamespace(ELF=ElfFixture))
    scanner = yara_engine.YaraXScanner.__new__(yara_engine.YaraXScanner)
    scanner.scanner = ScannerFixture()
    result = scanner.scan(Path("fixed.elf"))
    assert result["detected"] is False
    assert result["matches"] == []


def test_binding_absence_fails_closed(monkeypatch):
    monkeypatch.setitem(sys.modules, "yara_x", None)
    with pytest.raises(RuntimeError, match="YARA-X is required"):
        yara_engine.YaraXScanner.compile("rule Empty { condition: true }")


def test_adapter_does_not_invent_cve_or_record_for_custom_rule(monkeypatch):

    class ElfFixture:

        def __init__(self, target):
            pass

        def executable_ranges(self):
            return [(40, b"custom-rule-match")]

    class ScannerFixture:

        def scan(self, _data):
            match = SimpleNamespace(offset=0)
            pattern = SimpleNamespace(identifier="$a", matches=[match])
            rule = SimpleNamespace(identifier="CUSTOM_RULE",
                                   metadata=(),
                                   patterns=[pattern])
            return SimpleNamespace(matching_rules=[rule])

    monkeypatch.setitem(sys.modules, "factory.elf",
                        SimpleNamespace(ELF=ElfFixture))
    scanner = yara_engine.YaraXScanner.__new__(yara_engine.YaraXScanner)
    scanner.scanner = ScannerFixture()
    result = scanner.scan(Path("custom.elf"))

    assert result["matches"] == [{
        "cve": None,
        "record_id": None,
        "pattern": "$a",
        "file_offset": 40,
    }]


def test_adapter_sorts_mixed_valid_and_custom_metadata(monkeypatch):

    class ElfFixture:

        def __init__(self, path):
            pass

        def executable_ranges(self):
            return [(10, b"MATCH")]

    class ScannerFixture:

        def scan(self, _data):
            match = SimpleNamespace(offset=1)
            pattern = SimpleNamespace(identifier="$x", matches=[match])

            def rule(identifier):
                return SimpleNamespace(identifier=identifier,
                                       metadata=(("cve", "CVE-2099-12345"),),
                                       patterns=[pattern])

            return SimpleNamespace(matching_rules=[
                rule("VI_1234567890ABCDEF12345678"),
                rule("CUSTOM_RULE"),
            ])

    monkeypatch.setitem(sys.modules, "factory.elf",
                        SimpleNamespace(ELF=ElfFixture))
    scanner = yara_engine.YaraXScanner.__new__(yara_engine.YaraXScanner)
    scanner.scanner = ScannerFixture()
    result = scanner.scan(Path("example.elf"))
    assert len(result["matches"]) == 2
    assert {match["record_id"] for match in result["matches"]
           } == {None, "VI_1234567890ABCDEF12345678"}
