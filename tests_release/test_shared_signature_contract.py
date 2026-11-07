"""Contracts for the CVE-first, independently identified DB-record model."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from factory.signature_identity import new_record_id, record_sha256
from factory.yara_engine import source_from_packs
from tools import production_db
from tools.production_db import ReleaseRejected

CVE_A = "CVE-2026-12345"
CVE_B = "CVE-2026-67890"
CVE_TEST = "CVE-2026-77777"
PATTERN = "90 " * 27 + "90"
PLATFORM = {
    "os": "linux",
    "format": "ELF",
    "arch": "x86-64",
    "bits": 64,
    "abi": "sysv"
}


def _pack(cve, records):
    pack = {"schema_version": 3, "cve": cve, "records": records}
    return pack


def _record(cve, key, channel="production", pattern=PATTERN):
    return {
        "record_id":
            new_record_id(cve, key),
        "channel":
            channel,
        "source_type":
            "manual",
        "platform":
            dict(PLATFORM),
        "rules": [{
            "id": f"{key}-pattern",
            "hex": pattern,
            "length": 28,
            "fixed_bytes": 28
        }],
    }


def _write_cve(root: Path, cve: str, records=None, *, research=False):
    folder = root / cve
    folder.mkdir()
    if research:
        (folder / "research.json").write_text(json.dumps({"cve": cve}))
        return folder
    pack = _pack(cve, records or [_record(cve, "default")])
    (folder / "pack.json").write_text(json.dumps(pack))
    (folder / "rules-exec.yar").write_text(source_from_packs([pack]))
    return folder


def test_identical_pattern_is_duplicated_as_independent_cve_records():
    first = _pack(CVE_A, [_record(CVE_A, "default")])
    second = _pack(CVE_B, [_record(CVE_B, "default")])
    first_id = first["records"][0]["record_id"]
    second_id = second["records"][0]["record_id"]
    assert first_id != second_id
    source = source_from_packs([first, second])
    assert source.count("rule VI_") == 2
    assert source.count("{ " + PATTERN + " }") == 2
    assert source.count('cve = "CVE-2026-12345"') == 1
    assert source.count('cve = "CVE-2026-67890"') == 1
    assert "cves =" not in source
    assert production_db.match_cves({"cve": CVE_A}) == {CVE_A}
    assert production_db.match_cves({"cve": CVE_B}) == {CVE_B}


def test_one_cve_can_own_multiple_independent_records():
    pack = _pack(CVE_A, [
        _record(CVE_A, "x86-o2"),
        _record(CVE_A, "x86-o3", pattern="91 " * 27 + "91"),
    ])
    source = source_from_packs([pack])
    assert source.count("rule VI_") == 2
    assert source.count(f'cve = "{CVE_A}"') == 2
    assert len({record["record_id"] for record in pack["records"]}) == 2


def test_record_digest_is_independent_of_sibling_record_edits():
    first = _record(CVE_A, "x86-o2")
    second = _record(CVE_A, "x86-o3", pattern="91 " * 27 + "91")
    before = record_sha256(first)
    second["notes"] = "Changed without touching the first record"
    assert record_sha256(first) == before
    assert record_sha256(second) != before


@pytest.mark.parametrize("mutation", [
    lambda pack: pack.update(cve='CVE-2026-12345" } rule injected {'),
    lambda pack: pack["records"][0].update(channel="candidate"),
    lambda pack: pack["records"][0].update(record_id="shared-signature"),
    lambda pack: pack["records"][0].update(cves=[CVE_A, CVE_B]),
])
def test_invalid_record_ownership_or_channel_fails_closed(mutation):
    pack = _pack(CVE_A, [_record(CVE_A, "default")])
    mutation(pack)
    with pytest.raises(ValueError):
        source_from_packs([pack])


def test_duplicate_record_id_cannot_be_compiled_twice():
    pack = _pack(CVE_A, [_record(CVE_A, "default")])
    with pytest.raises(ValueError,
                       match="duplicate database record identifier"):
        source_from_packs([pack, pack])


def test_release_assembles_production_records_and_keeps_cve_counts(
        tmp_path, monkeypatch):
    root = tmp_path / "repo"
    signatures = root / "signatures"
    signatures.mkdir(parents=True)
    _write_cve(signatures, CVE_A, [_record(CVE_A, "default")])
    _write_cve(signatures, CVE_B, [_record(CVE_B, "default")])
    _write_cve(signatures, CVE_TEST,
               [_record(CVE_TEST, "test", channel="test")])
    research_cve = "CVE-2026-88888"
    _write_cve(signatures, research_cve, research=True)

    scanner = tmp_path / "scanner"
    scanner.write_text("native scanner stub")
    scanner.chmod(0o755)
    compiled_rules = {"count": 0}

    def scanner_boundary(args, **_):
        if args[1] == "compile":
            source = Path(args[args.index("--rules") + 1]).read_text()
            compiled_rules["count"] = source.count("rule VI_")
            Path(args[args.index("--output") +
                      1]).write_bytes(b"compiled fixture")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[1] == "verify":
            return SimpleNamespace(returncode=0,
                                   stdout=json.dumps({
                                       "engine": "yara-x",
                                       "rules": compiled_rules["count"]
                                   }),
                                   stderr="")
        raise AssertionError(args)

    monkeypatch.setattr(production_db.subprocess, "run", scanner_boundary)
    output = tmp_path / "database"
    result = production_db.assemble_git_tree(signatures, output, scanner)
    index = json.loads((output / "index.json").read_text())
    assert result["cve_count"] == 2
    assert result["record_count"] == 2
    assert index["cve_count"] == 2
    assert index["record_count"] == 2
    assert index["source_cves"] == sorted(
        [CVE_A, CVE_B, CVE_TEST, research_cve])
    assert index["excluded_from_channel_cves"] == sorted(
        [CVE_TEST, research_cve])
    assert {entry["cve"] for entry in index["entries"]} == {CVE_A, CVE_B}
    assert production_db.verify_release(output)["record_count"] == 2

    # Re-signing the outer hashes cannot make a duplicate record ID valid.
    index["entries"][1]["record_id"] = index["entries"][0]["record_id"]
    (output / "index.json").write_text(json.dumps(index))
    manifest = json.loads((output / "manifest.json").read_text())
    manifest["artifacts"]["index.json"] = production_db.sha256(output /
                                                               "index.json")
    (output / "manifest.json").write_text(json.dumps(manifest))
    (output / "SHA256SUMS").write_text("".join(
        f"{digest}  {name}\n"
        for name, digest in sorted(manifest["artifacts"].items())))
    with pytest.raises(ReleaseRejected, match="duplicate database record ID"):
        production_db.verify_release(output)


def test_factory_yara_validation_uses_complete_cve_record(
        monkeypatch, tmp_path):
    """Engine validation must use a complete CVE/record envelope, not a stub."""
    from factory import pipeline
    from factory.patterns import Pattern
    from types import SimpleNamespace

    captured = {}
    render = pipeline.source_from_packs

    def capture(packs):
        captured['pack'] = packs[0]
        return render(packs)

    class EmptyScanner:

        def scan(self, _path):
            return {'matches': []}

    monkeypatch.setattr(pipeline, 'source_from_packs', capture)
    monkeypatch.setattr(pipeline.YaraXScanner, 'compile',
                        lambda _source: EmptyScanner())
    monkeypatch.setattr(pipeline, 'scan_patterns',
                        lambda _patterns, _sample: [])
    cve = 'CVE-2099-12345'
    sample = SimpleNamespace(id='no-hit', path=tmp_path / 'empty.elf')
    pattern = Pattern.from_hex('90 90 90 90')
    result = pipeline.validate_yara_x(cve, [pattern], [sample])
    assert result['status'] == 'PASS', result
    pack = captured['pack']
    assert pack['schema_version'] == 3 and pack['cve'] == cve
    record, = pack['records']
    assert record['platform'] == PLATFORM
    assert record['channel'] == 'test'
    assert record['rules'] == [{
        'id': f'{cve}-pattern-0',
        'hex': '90 90 90 90',
        'length': 4,
        'fixed_bytes': 4
    }]
