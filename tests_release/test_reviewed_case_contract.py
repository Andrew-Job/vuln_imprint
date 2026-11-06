"""Our CVE admission policy, isolated from the external matching engine.

The fake scan responses below only test evidence decisions. They are not
native YARA-X scans and are never production admission results.
"""

import json
from pathlib import Path

import pytest

from factory.yara_engine import source_from_packs
from factory.signature_identity import new_record_id, record_sha256
from tools import production_db

CVE = "CVE-2025-12345"
HEX_PATTERN = " ".join(f"{i:02X}" for i in range(32))


def make_reviewed_case(tmp_path, monkeypatch):
    case = tmp_path / CVE
    specimens = case / "specimens"
    specimens.mkdir(parents=True)
    pack = {
        "schema_version":
            3,
        "cve":
            CVE,
        "records": [{
            "record_id":
                new_record_id(CVE),
            "channel":
                "production",
            "source_type":
                "factory",
            "supported_profiles": [{
                "compiler_family": family,
                "compiler_major": major,
                "optimization": opt
            }
                                   for family, majors in (("gcc", (11, 12)),
                                                          ("clang", (14, 15)))
                                   for major in majors
                                   for opt in ("-O2", "-O3")],
            "platform": {
                "os": "linux",
                "format": "ELF",
                "arch": "x86-64",
                "bits": 64,
                "abi": "sysv",
            },
            "rules": [{
                "id": f"{CVE}-0",
                "hex": HEX_PATTERN,
                "length": 32,
                "fixed_bytes": 32,
            }],
        }],
    }
    pack_path = case / "pack.json"
    rules_path = case / "rules-exec.yar"
    pack_path.write_text(json.dumps(pack))
    rules_path.write_text(source_from_packs([pack]))

    samples = []

    def add(label, name, *, compiler=None, version=None, static=False):
        # Each blob is distinct to test sample deduplication and provenance.
        path = specimens / f"{name}.bin"
        path.write_bytes(f"independent-test-specimen:{name}".encode())
        sample = {
            "id": name,
            "label": label,
            "lineage": f"independent-{name}",
            "path": f"specimens/{path.name}",
            "sha256": production_db.sha256(path),
            "origin": "https://example.org/source/commit/123",
            "split": "independent_holdout",
            "label_basis": ("independent_unrelated"
                            if label == "unrelated" else "patch_state"),
            "source_commit": "a" * 40,
            "version": version or ("1.2.0" if label != "fixed" else "1.2.1"),
        }
        if compiler is not None:
            family, major, opt = compiler
            sample['binary_kind'] = 'source_built_elf'
            sample['artifact_role'] = 'host_0'
            sample["build_profile"] = {
                "compiler_family": family,
                "compiler_version": f"{major}.0.1",
                "compiler_major": major,
                "compiler_binary_sha256": "b" * 64,
                "compiler_target": "x86_64-linux-gnu",
                "optimization": opt,
            }
            sample["build_provenance"] = {
                "schema_version":
                    1,
                "source": {
                    "type": "git",
                    "commit": sample["source_commit"]
                },
                "source_provenance_sha256":
                    "f" * 64,
                "toolchain": {
                    "family": family,
                    "version": f"{major}.0.1",
                    "binary_sha256": "b" * 64,
                    "target": "x86_64-linux-gnu",
                    "optimization": opt,
                    "executable": f"/usr/bin/{family}-{major}",
                },
                "artifacts": {
                    "module.o": "a" * 64,
                    "libcomponent.a": "d" * 64,
                    "host_0": sample["sha256"],
                    "host_1": "e" * 64
                },
                "commands": [[
                    f"/usr/bin/{family}-{major}", opt, "main.c", "-o", "host_0"
                ]],
            }
        if label == "backport":
            sample["patch_commit"] = "c" * 40
        if static:
            sample["binary_kind"] = "stripped_third_party_executable"
            sample["linkage"] = "static"
        samples.append(sample)
        return sample

    for family, majors in (("gcc", (11, 12)), ("clang", (14, 15))):
        for major in majors:
            for opt in ("-O2", "-O3"):
                lane = (family, major, opt)
                add("affected",
                    f"affected-{family}-{major}-{opt}",
                    compiler=lane)
                add("fixed", f"fixed-{family}-{major}-{opt}", compiler=lane)
    add("backport", "backport-same-version", compiler=("gcc", 11, "-O2"))
    add("affected", "independent-static-product", static=True)
    for index in range(20):
        add("unrelated", f"unrelated-{index:02d}")

    spec = {
        "schema_version":
            3,
        "cve":
            CVE,
        "rules_sha256":
            production_db.sha256(rules_path),
        "pack_sha256":
            production_db.sha256(pack_path),
        "training_lineages": ["training-revision-unrelated-to-holdouts"],
        "samples":
            samples,
        "records": [{
            "record_id": pack["records"][0]["record_id"],
            "record_sha256": record_sha256(pack["records"][0]),
            "training_lineages": ["training-revision-unrelated-to-holdouts"],
            "sample_ids": [sample["id"] for sample in samples],
        }],
    }
    evidence = case / "reviewed-evidence.json"
    evidence.write_text(json.dumps(spec))

    def fake_native_scan(scanner, rules, target, **kwargs):
        # Simulate the scanner's output schema, not YARA-X matching semantics.
        positive = (target.stem.startswith("affected-") or
                    target.stem == "independent-static-product")
        return {
            "matches": ([{
                "cve": CVE,
                "record_id": new_record_id(CVE),
                "executable": True
            }] if positive else [])
        }

    monkeypatch.setattr(production_db, "native_scan", fake_native_scan)
    # Policy unit tests isolate attestation/ELF parsing; independent tests
    # exercise actual bytes and real external tools in integration CI.
    monkeypatch.setattr(production_db, "verify_static_product", lambda *_: None)
    monkeypatch.setattr(production_db, "verify_third_party_attestation",
                        lambda *_: None)
    scanner = case / "scanner-placeholder"
    scanner.write_bytes(b"scanner-hash-only")
    return case, spec, scanner


def test_reviewed_case_accepts_complete_independent_matrix(
        tmp_path, monkeypatch):
    case, spec, scanner = make_reviewed_case(tmp_path, monkeypatch)
    result = production_db.validate_case(case, scanner)
    assert result["counts"] == {
        "affected": 9,
        "fixed": 8,
        "backport": 1,
        "unrelated": 20,
    }
    assert len(result["records"][0]["tested_build_profiles"]["affected"]) == 8
    assert len(result["records"][0]["tested_build_profiles"]["fixed"]) == 8
    assert (sum(
        item["independent_static_product"] for item in result["samples"]) == 1)


@pytest.mark.parametrize("problem,expected", [
    ("missing_fixed_lane", "missing supported fixed lanes"),
    ("training_lineage_reused",
     "independent holdout duplicates training lineage"),
    ("bad_backport_version", "backport must fix an affected source-version"),
    ("duplicated_specimen", "duplicate binary digest"),
    ("specimen_escapes_case", "outside case dir"),
    ("forged_hash", "specimen SHA-256 mismatch"),
])
def test_reviewed_case_rejects_insufficient_evidence(tmp_path, monkeypatch,
                                                     problem, expected):
    case, spec, scanner = make_reviewed_case(tmp_path, monkeypatch)
    sample = spec["samples"]
    if problem == "missing_fixed_lane":
        sample[:] = [r for r in sample if r["id"] != "fixed-gcc-11--O2"]
        spec["records"][0]["sample_ids"] = [row["id"] for row in sample]
    elif problem == "training_lineage_reused":
        spec["training_lineages"] = [sample[0]["lineage"]]
    elif problem == "bad_backport_version":
        next(r for r in sample if r["label"] == "backport")["version"] = "0.0.0"
    elif problem == "duplicated_specimen":
        sample[1]["sha256"] = sample[0]["sha256"]
        # Reuse the exact file contents and therefore its computed digest.
        original = (case / sample[0]["path"]).read_bytes()
        (case / sample[1]["path"]).write_bytes(original)
    elif problem == "specimen_escapes_case":
        sample[0]["path"] = "../../outside.bin"
    elif problem == "forged_hash":
        sample[0]["sha256"] = "0" * 64
    (case / "reviewed-evidence.json").write_text(json.dumps(spec))
    with pytest.raises(production_db.ReleaseRejected, match=expected):
        production_db.validate_case(case, scanner)


def test_fixed_binary_match_fails_evidence_gate(tmp_path, monkeypatch):
    case, spec, scanner = make_reviewed_case(tmp_path, monkeypatch)
    original_scan = production_db.native_scan

    def incorrect_scan(scanner, rules, target, **kwargs):
        if target.stem.startswith("fixed-"):
            return {
                "matches": [{
                    "cve": CVE,
                    "record_id": new_record_id(CVE),
                    "executable": True
                }]
            }
        return original_scan(scanner, rules, target, **kwargs)

    monkeypatch.setattr(production_db, "native_scan", incorrect_scan)
    with pytest.raises(production_db.ReleaseRejected,
                       match="fixed sample misclassified"):
        production_db.validate_case(case, scanner)


def test_fixed_lineage_independence_cannot_be_satisfied_by_backport(
        tmp_path, monkeypatch):
    """A separate backport does not provide a second independent fixed lineage."""
    case, spec, scanner = make_reviewed_case(tmp_path, monkeypatch)
    for row in spec["samples"]:
        if row["label"] == "fixed":
            row["lineage"] = "shared-fixed-build-lineage"
    (case / "reviewed-evidence.json").write_text(json.dumps(spec))
    with pytest.raises(production_db.ReleaseRejected,
                       match="insufficient affected/fixed lineages"):
        production_db.validate_case(case, scanner)


def test_admission_rejects_noncanonical_platform_metadata(
        tmp_path, monkeypatch):
    case, spec, scanner = make_reviewed_case(tmp_path, monkeypatch)
    pack = json.loads((case / "pack.json").read_text())
    pack["records"][0]["platform"]["compiler"] = "gcc"
    (case / "pack.json").write_text(json.dumps(pack))
    with pytest.raises(production_db.ReleaseRejected,
                       match="unsupported platform"):
        production_db.validate_case(case, scanner)


def _add_second_record(case, spec):
    pack_path = case / "pack.json"
    pack = json.loads(pack_path.read_text())
    second = json.loads(json.dumps(pack["records"][0]))
    second["record_id"] = new_record_id(CVE, "independent-second-record")
    second["supported_profiles"] = [second["supported_profiles"][0]]
    pack["records"].append(second)
    pack_path.write_text(json.dumps(pack))
    rule_path = case / "rules-exec.yar"
    rule_path.write_text(source_from_packs([pack]))
    spec["pack_sha256"] = production_db.sha256(pack_path)
    spec["rules_sha256"] = production_db.sha256(rule_path)
    spec["records"].append({
        "record_id": second["record_id"],
        "record_sha256": record_sha256(second),
        "training_lineages": list(spec["training_lineages"]),
        "sample_ids": [sample["id"] for sample in spec["samples"]],
    })
    (case / "reviewed-evidence.json").write_text(json.dumps(spec))
    return second


def test_each_record_requires_independent_positive_evidence(
        tmp_path, monkeypatch):
    case, spec, scanner = make_reviewed_case(tmp_path, monkeypatch)
    second = _add_second_record(case, spec)
    with pytest.raises(production_db.ReleaseRejected,
                       match=second["record_id"] +
                       ".*affected sample misclassified"):
        production_db.validate_case(case, scanner)


def test_record_evidence_is_bound_to_record_sha256(tmp_path, monkeypatch):
    case, spec, scanner = make_reviewed_case(tmp_path, monkeypatch)
    spec["records"][0]["record_sha256"] = "0" * 64
    (case / "reviewed-evidence.json").write_text(json.dumps(spec))
    with pytest.raises(production_db.ReleaseRejected,
                       match="record SHA-256 mismatch"):
        production_db.validate_case(case, scanner)


def test_supported_profiles_are_not_shared_between_sibling_records(
        tmp_path, monkeypatch):
    case, spec, scanner = make_reviewed_case(tmp_path, monkeypatch)
    second = _add_second_record(case, spec)
    # Make sibling positives independently valid, then remove its only
    # fixed profile. The other record still covers the full matrix.
    original = production_db.native_scan

    def both_records(scanner, rules, target, **kwargs):
        response = original(scanner, rules, target, **kwargs)
        if response["matches"]:
            response["matches"].append({
                "cve": CVE,
                "record_id": second["record_id"],
                "executable": True
            })
        return response

    monkeypatch.setattr(production_db, "native_scan", both_records)
    spec["records"][1]["sample_ids"] = [
        row["id"] for row in spec["samples"] if row["id"] != "fixed-gcc-11--O2"
    ]
    (case / "reviewed-evidence.json").write_text(json.dumps(spec))
    with pytest.raises(production_db.ReleaseRejected,
                       match=second["record_id"] +
                       ".*missing supported fixed lanes"):
        production_db.validate_case(case, scanner)
