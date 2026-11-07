"""First-party record independence and supported platform contracts."""
import json
from pathlib import Path

import pytest

from factory.database import load_included_packs, merge_packs
from factory.yara_engine import source_from_packs
from factory.signature_identity import new_record_id


def make_pack(root: Path,
              profile: dict,
              *,
              cve: str = "CVE-2026-12345",
              record_key: str | None = None):
    name = f"case-{len(list(root.iterdir()))}"
    folder = root / name
    folder.mkdir()
    key = record_key or name
    pack = {
        "schema_version":
            3,
        "cve":
            cve,
        "records": [{
            "record_id":
                new_record_id(cve, key),
            "channel":
                "test",
            "source_type":
                "factory",
            "platform":
                profile,
            "rules": [{
                "id": f"{name}-pattern",
                "hex": "48 85 C0 75 11 48 83 C4 08"
            }],
        }],
    }
    (folder / "pack.json").write_text(json.dumps(pack))
    (folder / "rules-exec.yar").write_text(source_from_packs([pack]))
    return folder, pack


PLATFORM = {
    "os": "linux", "format": "ELF", "arch": "x86-64",
    "bits": 64, "abi": "sysv"
}


def test_two_independent_records_are_owned_by_one_cve(tmp_path):
    cases = tmp_path / "cases"
    cases.mkdir()
    first_dir, first = make_pack(cases, dict(PLATFORM))
    second_dir, second = make_pack(cases, dict(PLATFORM))
    snapshot = tmp_path / "database"
    result = merge_packs([first_dir, second_dir], snapshot, channel="test")
    assert result["cve_count"] == 1
    assert result["record_count"] == 2
    assert len({entry["pack_dir"] for entry in result["entries"]}) == 2
    assert {pack["records"][0]["record_id"]
            for pack in load_included_packs(snapshot)} == {
                first["records"][0]["record_id"],
                second["records"][0]["record_id"]
            }


def test_unsupported_machine_profile_is_rejected(tmp_path):
    cases = tmp_path / "cases"
    cases.mkdir()
    with pytest.raises(ValueError, match="unsupported ELF platform"):
        make_pack(cases, {**PLATFORM, "arch": "aarch64"})


def test_compiler_versions_are_distinct_records_for_same_cve(tmp_path):
    root = tmp_path / "cases"
    root.mkdir()
    first, _ = make_pack(root, dict(PLATFORM))
    second, _ = make_pack(root, dict(PLATFORM))
    # Compiler-specific provenance belongs to the record rather than being
    # encoded as extra keys in the executable platform profile.
    for directory, version in ((first, "11.4"), (second, "12.3")):
        path = directory / "pack.json"
        pack = json.loads(path.read_text())
        pack["records"][0]["supported_profiles"] = [{
            "compiler_family": "gcc", "compiler_version": version,
            "optimization": "-O2"
        }]
        path.write_text(json.dumps(pack))
    output = tmp_path / "db"
    assert merge_packs([first, second], output,
                       channel="test")["cve_count"] == 1
    packs = load_included_packs(output)
    assert len(packs) == 2
    assert {pack["records"][0]["supported_profiles"][0]["compiler_version"]
            for pack in packs} == {"11.4", "12.3"}


def test_duplicate_record_id_and_corrupted_profile_are_rejected(tmp_path):
    root = tmp_path / "cases"
    root.mkdir()
    profile = dict(PLATFORM)
    first, _ = make_pack(root, profile, record_key="same")
    second, _ = make_pack(root, profile, record_key="same")
    with pytest.raises(ValueError, match="duplicate database record ID"):
        merge_packs([first, second], tmp_path / "duplicate", channel="test")
    db = tmp_path / "valid"
    merge_packs([first], db, channel="test")
    index = json.loads((db / "index.json").read_text())
    index["entries"][0]["platform"]["arch"] = "aarch64"
    (db / "index.json").write_text(json.dumps(index))
    with pytest.raises(ValueError, match="inconsistent"):
        load_included_packs(db)

