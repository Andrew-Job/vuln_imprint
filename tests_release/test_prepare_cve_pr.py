"""First-party tests of PR preparation: no substitute YARA-X engine."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from tools.prepare_cve_pr import prepare
from tools.production_db import ReleaseRejected


def _fixture(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "signatures" / "validated").mkdir(parents=True)
    case = tmp_path / "cases" / "CVE-2026-25646"
    case.mkdir(parents=True)
    (case / "pack.json").write_text(json.dumps({"cve": case.name}))
    (case / "rules-exec.yar").write_text("rule test { condition: true }\n")
    (case / "reviewed-evidence.json").write_text("{}\n")
    scanner = tmp_path / "scanner"
    scanner.write_text("native scanner fixture, not executed")
    scanner.chmod(0o755)
    return repo, case, scanner


def test_rejected_validation_cannot_write_production_source(tmp_path):
    repo, case, scanner = _fixture(tmp_path)
    with patch("tools.prepare_cve_pr.validate_case", side_effect=ReleaseRejected("no holdout")):
        with pytest.raises(ReleaseRejected, match="no holdout"):
            prepare(case, scanner, repo)
    assert not (repo / "signatures" / "validated" / case.name).exists()


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


def test_successful_native_evidence_can_prepare_pr_source(tmp_path):
    repo, case, scanner = _fixture(tmp_path)
    # Isolate transport/rollback behavior: validation and Git gate have their
    # own dedicated tests and are not replaced in release CI.
    with patch("tools.prepare_cve_pr.validate_case", return_value={
        "quality": "CVE_SPECIFIC_VALIDATED", "samples": [1, 2, 3],
    }), patch("tools.prepare_cve_pr.check", return_value=[case.name]):
        result = prepare(case, scanner, repo)
    assert result["status"] == "READY_FOR_REVIEW"
    assert result["independent_samples"] == 3
    assert sorted(x.name for x in (repo / "signatures" / "validated" / case.name).iterdir()) == [
        "pack.json", "reviewed-evidence.json", "rules-exec.yar"
    ]


def test_source_tree_gate_failure_rolls_back(tmp_path):
    repo, case, scanner = _fixture(tmp_path)
    with patch("tools.prepare_cve_pr.validate_case", return_value={
        "quality": "CVE_SPECIFIC_VALIDATED", "samples": [],
    }), patch("tools.prepare_cve_pr.check", side_effect=ReleaseRejected("source gate failed")):
        with pytest.raises(ReleaseRejected, match="source gate failed"):
            prepare(case, scanner, repo)
    assert not (repo / "signatures" / "validated" / case.name).exists()
