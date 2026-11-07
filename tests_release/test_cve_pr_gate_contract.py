"""PR gate validates CVE source changes without quality-state promotion."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import check_cve_pr
from tools.production_db import ReleaseRejected

CVE = "CVE-2026-12345"
BASE = "a" * 40


def test_changed_cve_directory_cannot_be_removed_without_source_record(
        tmp_path, monkeypatch):
    monkeypatch.setattr(check_cve_pr, "check", lambda *_args, **_kw: [])
    monkeypatch.setattr(
        check_cve_pr.subprocess, "run", lambda *_args, **_kw: SimpleNamespace(
            stdout=f"signatures/{CVE}/pack.json\n"))
    with pytest.raises(ReleaseRejected, match="preserve the CVE source record"):
        check_cve_pr.gate(tmp_path, BASE)


def test_unchanged_cve_does_not_require_a_quality_status(tmp_path, monkeypatch):
    directory = tmp_path / "signatures" / CVE
    directory.mkdir(parents=True)
    monkeypatch.setattr(check_cve_pr, "check", lambda *_args, **_kw: [])
    monkeypatch.setattr(
        check_cve_pr.subprocess, "run",
        lambda *_args, **_kw: SimpleNamespace(stdout="README.md\n"))
    assert check_cve_pr.gate(tmp_path, BASE) == []


def test_changed_cve_passes_when_source_directory_is_preserved(
        tmp_path, monkeypatch):
    directory = tmp_path / "signatures" / CVE
    directory.mkdir(parents=True)
    monkeypatch.setattr(check_cve_pr, "check", lambda *_args, **_kw: [])
    monkeypatch.setattr(
        check_cve_pr.subprocess, "run", lambda *_args, **_kw: SimpleNamespace(
            stdout=f"signatures/{CVE}/rules-exec.yar\n"))
    assert check_cve_pr.gate(tmp_path, BASE) == [CVE]
