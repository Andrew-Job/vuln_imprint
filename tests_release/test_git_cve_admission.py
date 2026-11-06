"""First-party Git membership and pre-merge admission contracts."""

import json
from pathlib import Path

import pytest

from scripts.check_native_cve_corpus import run
from scripts.check_validated_signatures import check
from tools.manual_rules import initialize
from tools.production_db import ReleaseRejected, sha256


def project(tmp_path):
    target = tmp_path / "signatures" / "validated"
    target.mkdir(parents=True)
    return target


def create_validated_manual_signature(target, cve="CVE-2026-12345"):
    case = target / cve
    initialize(cve, [" ".join(["90"] * 28)], case)
    pack_path = case / "pack.json"
    pack = json.loads(pack_path.read_text())
    pack["status"] = "CVE_SPECIFIC_VALIDATED"
    pack_path.write_text(json.dumps(pack))
    rule_path = case / "rules-exec.yar"
    rule_path.write_text(rule_path.read_text().replace(
        "CANDIDATE_ONLY", "CVE_SPECIFIC_VALIDATED"))
    evidence = {
        "schema_version": 2,
        "cve": cve,
        "quality": "CVE_SPECIFIC_VALIDATED",
        "pack_sha256": sha256(pack_path),
        "rules_sha256": sha256(rule_path),
        "training_lineages": ["independent-build-family-1"],
        "samples": [{
            "label": "affected",
            "split": "independent_holdout"
        }],
    }
    (case / "reviewed-evidence.json").write_text(json.dumps(evidence))
    return case


def test_only_git_validated_directories_are_published(tmp_path):
    target = project(tmp_path)
    assert check(tmp_path) == []
    create_validated_manual_signature(target, "CVE-2026-12345")
    create_validated_manual_signature(target, "CVE-2026-67890")
    assert check(tmp_path) == ["CVE-2026-12345", "CVE-2026-67890"]


def test_research_cannot_be_merged_into_release_tree(tmp_path):
    project(tmp_path)
    (tmp_path / "cve_queue").mkdir()
    with pytest.raises(ReleaseRejected, match="unvalidated research"):
        check(tmp_path)


def test_fork_research_directory_cannot_enter_main(tmp_path):
    project(tmp_path)
    (tmp_path / "research" / "catalog_recent").mkdir(parents=True)
    with pytest.raises(ReleaseRejected, match="unvalidated research"):
        check(tmp_path)


def test_changed_rule_requires_new_evidence_binding(tmp_path):
    target = project(tmp_path)
    case = create_validated_manual_signature(target)
    assert check(tmp_path) == [case.name]
    rule = case / "rules-exec.yar"
    rule.write_text(rule.read_text().replace("90 90", "91 90", 1))
    with pytest.raises(ReleaseRejected):
        check(tmp_path)


def test_proposal_and_incomplete_case_cannot_be_committed(tmp_path):
    target = project(tmp_path)
    case = target / "CVE-2026-12345"
    initialize(case.name, [" ".join(["90"] * 28)], case)
    with pytest.raises(ReleaseRejected, match="exactly three"):
        check(tmp_path)
    (case / "reviewed-evidence.json").write_text("{}")
    with pytest.raises(ReleaseRejected, match="manual rule must be approved"):
        check(tmp_path)


def test_native_ci_requires_actual_corpus_when_git_contains_cves(tmp_path):
    target = project(tmp_path)
    create_validated_manual_signature(target)
    lock = tmp_path / "release"
    lock.mkdir()
    (lock / "reviewed-corpus.lock.json").write_text(
        json.dumps({
            "schema_version": 2,
            "archive_url": None,
            "archive_sha256": None,
        }))
    with pytest.raises(ReleaseRejected, match="immutable HTTPS corpus URL"):
        run(tmp_path, tmp_path / "native-scanner", "reviewed.example.org")


def test_release_assembly_contains_every_validated_git_cve(
        tmp_path, monkeypatch):
    """Exercise composition/integrity without substituting for native YARA-X CI."""
    from types import SimpleNamespace
    from tools import production_db

    source = project(tmp_path)
    create_validated_manual_signature(source, "CVE-2026-67890")
    create_validated_manual_signature(source, "CVE-2026-12345")
    scanner = tmp_path / "native-scanner"
    scanner.write_text("#!/bin/sh\nexit 0\n")
    scanner.chmod(0o755)
    commands = []

    def scanner_boundary(argv, **kwargs):
        commands.append(argv)
        if argv[1] == "compile":
            compiled = Path(argv[argv.index("--output") + 1])
            source_bytes = Path(argv[argv.index("--rules") + 1]).read_text()
            assert "CVE_2026_12345" in source_bytes
            assert "CVE_2026_67890" in source_bytes
            compiled.write_bytes(b"synthetic compiled test fixture")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if argv[1] == "verify":
            return SimpleNamespace(returncode=0,
                                   stdout=json.dumps({
                                       "engine": "yara-x",
                                       "rules": 2
                                   }),
                                   stderr="")
        raise AssertionError(f"unexpected scanner command: {argv}")

    monkeypatch.setattr(production_db.subprocess, "run", scanner_boundary)
    output = tmp_path / "output"
    result = production_db.assemble_validated(source, output, scanner)
    assert result["cve_count"] == 2
    assert production_db.verify_release(output)["cve_count"] == 2
    index = json.loads((output / "index.json").read_text())
    assert [entry["cve"] for entry in index["entries"]
           ] == ["CVE-2026-12345", "CVE-2026-67890"]
    assert [call[1] for call in commands] == ["compile", "verify"]


def test_release_assembly_refuses_empty_and_noncanonical_source(tmp_path):
    from tools.production_db import assemble_validated

    source = project(tmp_path)
    executable = tmp_path / "native-scanner"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    with pytest.raises(ReleaseRejected, match="no Git-validated CVEs"):
        assemble_validated(source, tmp_path / "database", executable)
    assert not (tmp_path / "database").exists()
    alternative = tmp_path / "arbitrary-directory"
    alternative.mkdir()
    with pytest.raises(ReleaseRejected, match="canonical validated"):
        assemble_validated(alternative, tmp_path / "database", executable)
