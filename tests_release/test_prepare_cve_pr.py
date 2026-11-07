"""PR preparation tests for CVE-owned records and native source compilation."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tools.prepare_cve_pr import prepare
from tools.manual_rules import initialize
from tools.production_db import ReleaseRejected

PATTERN = ' '.join(f'{value:02X}' for value in range(32))


def _fixture(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "signatures").mkdir(parents=True)
    case = tmp_path / "cases" / "CVE-2026-25646"
    initialize("CVE-2026-25646", [PATTERN], case, channel="test")
    scanner = tmp_path / "scanner"
    scanner.write_text("native scanner fixture, intercepted in tests")
    scanner.chmod(0o755)
    return repo, case, scanner


def _native_compile(monkeypatch):

    def run(argv, **_kwargs):
        output = Path(argv[argv.index("--output") + 1])
        output.write_bytes(b"compiled fixture")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("tools.prepare_cve_pr.subprocess.run", run)


def test_missing_native_scanner_fails_closed(tmp_path):
    repo, case, scanner = _fixture(tmp_path)
    scanner.unlink()
    with pytest.raises(ReleaseRejected, match="native YARA-X"):
        prepare(case, scanner, repo)


def test_symlinked_case_input_rejected(tmp_path):
    repo, case, scanner = _fixture(tmp_path)
    (case / "rules-exec.yar").unlink()
    (case / "rules-exec.yar").symlink_to("pack.json")
    with pytest.raises(ReleaseRejected, match="symlinked"):
        prepare(case, scanner, repo)


def test_successful_native_compile_prepares_test_record(tmp_path, monkeypatch):
    repo, case, scanner = _fixture(tmp_path)
    _native_compile(monkeypatch)
    result = prepare(case, scanner, repo)
    assert result["status"] == "READY_FOR_REVIEW"
    assert result["record_count"] == 1
    assert result["channels"] == ["test"]
    assert sorted(
        path.name for path in (repo / "signatures" / case.name).iterdir()) == [
            "pack.json", "rules-exec.yar"
        ]


def test_second_record_for_existing_cve_is_merged_independently(
        tmp_path, monkeypatch):
    repo, case, scanner = _fixture(tmp_path)
    _native_compile(monkeypatch)
    prepare(case, scanner, repo)
    second = tmp_path / "cases-second" / case.name
    initialize(case.name, [PATTERN],
               second,
               channel="test",
               record_key="second")
    result = prepare(second, scanner, repo)
    merged = json.loads(
        (repo / "signatures" / case.name / "pack.json").read_text())
    assert result["record_count"] == 2
    assert len(merged["records"]) == 2
    assert len({record["record_id"] for record in merged["records"]}) == 2


def test_source_tree_gate_failure_rolls_back(tmp_path, monkeypatch):
    repo, case, scanner = _fixture(tmp_path)
    _native_compile(monkeypatch)
    with patch("tools.prepare_cve_pr.check",
               side_effect=[[], ReleaseRejected("source gate failed")]):
        with pytest.raises(ReleaseRejected, match="source gate failed"):
            prepare(case, scanner, repo)
    assert not (repo / "signatures" / case.name).exists()
