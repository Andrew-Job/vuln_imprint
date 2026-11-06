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
            rule = SimpleNamespace(identifier="CVE_2099_12345",
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
        "rule": "CVE_2099_12345",
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
