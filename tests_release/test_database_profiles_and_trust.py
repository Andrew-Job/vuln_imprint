"""Regression tests of VulnImprint profile identity and trust admission."""
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


def test_two_platform_records_are_owned_by_one_cve(tmp_path):
    cases = tmp_path / "cases"
    cases.mkdir()
    x86, first = make_pack(cases, {
        "format": "ELF",
        "arch": "x86-64",
        "bits": 64
    })
    arm, second = make_pack(cases, {
        "format": "ELF",
        "arch": "aarch64",
        "bits": 64
    })
    snapshot = tmp_path / "database"
    result = merge_packs([x86, arm], snapshot, channel="test")
    assert result["cve_count"] == 1
    assert result["record_count"] == 2
    assert len({x["pack_dir"] for x in result["entries"]}) == 2
    assert {
        p["records"][0]["record_id"] for p in load_included_packs(snapshot)
    } == {first["records"][0]["record_id"], second["records"][0]["record_id"]}
    text = (snapshot / "database.yar").read_text()
    assert text.count("rule VI_") == 2


def test_compiler_versions_are_distinct_records_for_same_cve(tmp_path):
    root = tmp_path / "cases"
    root.mkdir()
    first, _ = make_pack(
        root, {
            "format": "ELF",
            "arch": "x86-64",
            "compiler": "gcc",
            "compiler_version": "11.4",
            "optimization": "O2"
        })
    second, _ = make_pack(
        root, {
            "format": "ELF",
            "arch": "x86-64",
            "compiler": "gcc",
            "compiler_version": "12.3",
            "optimization": "O2"
        })
    output = tmp_path / "db"
    assert merge_packs([first, second], output,
                       channel="test")["cve_count"] == 1
    assert len(load_included_packs(output)) == 2
    names = [
        line.strip()
        for line in (output / "database.yar").read_text().splitlines()
        if line.startswith("rule ")
    ]
    assert len(names) == len(set(names)) == 2


def test_duplicate_record_id_and_corrupted_profile_are_rejected(tmp_path):
    root = tmp_path / "cases"
    root.mkdir()
    profile = {"format": "ELF", "arch": "x86-64", "bits": 64}
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


def _repo_api(*,
              approve=True,
              tags=True,
              deployment=True,
              bypass=False,
              style=True):

    def get(endpoint):
        if endpoint == "repos/user/vuln_imprint":
            return {"private": False, "default_branch": "main"}
        if endpoint.endswith("/immutable-releases"):
            return {"enabled": True}
        if endpoint.endswith("/branches/main/protection"):
            return {
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews": True
                },
                "required_status_checks": {
                    "contexts": (["google-style"] if style else []) +
                                ["offline", "security", "native"]
                },
                "enforce_admins": {
                    "enabled": True
                }
            }
        if "rulesets?includes_parents" in endpoint:
            return [{"target": "tag", "enforcement": "active", "id": 17}]
        if endpoint.endswith("/rulesets/17"):
            return {
                "conditions": {
                    "ref_name": {
                        "include": ["refs/tags/v*"],
                        "exclude": []
                    }
                },
                "rules": [{
                    "type": "deletion"
                }, {
                    "type": "update" if tags else "creation"
                }],
                "bypass_actors": [{
                    "actor_id": 1
                }] if bypass else []
            }
        if endpoint.endswith("/environments/production"):
            return {
                "protection_rules": [{
                    "type":
                        "required_reviewers",
                    "prevent_self_review":
                        approve,
                    "reviewers": [{
                        "type": "User",
                        "reviewer": {
                            "login": "reviewer"
                        }
                    }]
                }],
                "deployment_branch_policy": {
                    "custom_branch_policies": deployment
                }
            }
        if endpoint.endswith("/deployment-branch-policies"):
            return {"branch_policies": [{"type": "tag", "name": "v*"}]}
        raise AssertionError(endpoint)

    return get
