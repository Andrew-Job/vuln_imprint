"""Safety and source-aggregation contracts owned by VulnImprint."""

import json
from pathlib import Path

import pytest

from factory.database import load_included_packs, merge_packs
from factory.yara_engine import source_from_packs


def _pack(cve: str, *, hex_pattern: str = "48 83 EC 28") -> dict:
    return {
        "cve": cve,
        "status": "CANDIDATE_ONLY",
        "platform": {
            "format": "ELF",
            "arch": "x86-64",
            "bits": 64
        },
        "rules": [{
            "hex": hex_pattern
        }],
    }


def test_rule_aggregation_is_deterministic_and_preserves_cve_identity():
    first = _pack("CVE-2025-10001")
    second = _pack("CVE-2026-20002", hex_pattern="90 90 CC 90")
    merged = source_from_packs([first, second])
    assert merged == source_from_packs([first, second])
    assert merged.count("\nrule ") == 1
    assert merged.count("    any of them") == 2
    assert merged.index("CVE-2025-10001") < merged.index("CVE-2026-20002")


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(cve='CVE-2025-12345" } rule injected { condition: true }'
                      ),
    lambda p: p.update(status='CANDIDATE_ONLY"\n condition: true'),
    lambda p: p["rules"][0].update(hex='48 8B } condition: true'),
])
def test_manifest_fields_cannot_inject_yara_rules(mutation):
    candidate = _pack("CVE-2025-12345")
    mutation(candidate)
    with pytest.raises(ValueError):
        source_from_packs([candidate])


def test_duplicate_cve_rule_identifiers_are_rejected():
    pack = _pack("CVE-2025-12345")
    with pytest.raises(ValueError, match="duplicate rule"):
        source_from_packs([pack, pack])


def test_index_read_only_access_to_snapshot_with_cve_binding(tmp_path):
    case = tmp_path / "CVE-2025-12345"
    case.mkdir()
    pack = _pack("CVE-2025-12345")
    (case / "pack.json").write_text(json.dumps(pack))
    (case / "rules-exec.yar").write_text(source_from_packs([pack]))
    db = tmp_path / "db"
    merge_packs([case], db, allow_experimental=True)
    assert load_included_packs(db) == [pack]

    index_path = db / "index.json"
    original = json.loads(index_path.read_text())
    for bad in ("../../outside", str(case.resolve()), "packs/../../outside"):
        modified = json.loads(json.dumps(original))
        modified["entries"][0]["pack_dir"] = bad
        index_path.write_text(json.dumps(modified))
        with pytest.raises(ValueError, match="unsafe pack_dir"):
            load_included_packs(db)

    modified = json.loads(json.dumps(original))
    modified["entries"][0]["cve"] = "CVE-2099-99999"
    index_path.write_text(json.dumps(modified))
    with pytest.raises(ValueError, match="inconsistent"):
        load_included_packs(db)
