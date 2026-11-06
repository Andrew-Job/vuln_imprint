#!/usr/bin/env python3
"""Validate the CVE-owned Git source tree and optional review artifacts.

The source model has only two database channels: test and production. This
checker validates structure and provenance; it does not classify detection
quality or gate production inclusion on an evidence-status label.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.production_db import CVE, ReleaseRejected, sha256, validate_source_pack

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ("research", "cve_queue", "catalog_recent", "catalog",
            "signatures/staging")


def check(root: Path = ROOT) -> list[str]:
    """Validate all CVE source records and return CVEs with review artifacts."""
    for name in RESEARCH:
        location = root / name
        if location.exists():
            raise ReleaseRejected(f"untracked research in release tree: {name}")
    signatures = root / "signatures"
    if not signatures.is_dir() or signatures.is_symlink():
        raise ReleaseRejected("Git signature directory is missing")

    reviewed_cves = []
    record_ids = set()
    for case in sorted(signatures.iterdir()):
        if case.name == "README.md" and case.is_file():
            continue
        if (case.is_symlink() or not case.is_dir() or
                not CVE.fullmatch(case.name)):
            raise ReleaseRejected(
                f"unexpected entry in Git signature tree: {case.name}")
        files = {path.name for path in case.iterdir()}
        if any((case / name).is_symlink() or not (case / name).is_file()
               for name in files):
            raise ReleaseRejected(
                f"{case.name}: source entries must be regular files")
        if files == {"research.json"}:
            research_path = case / "research.json"
            if research_path.stat().st_size > 1 << 20:
                raise ReleaseRejected(
                    f"{case.name}: oversized research metadata")
            try:
                research = json.loads(research_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ReleaseRejected(
                    f"{case.name}: invalid research JSON") from exc
            if not isinstance(research,
                              dict) or research.get("cve") != case.name:
                raise ReleaseRejected(
                    f"{case.name}: invalid research CVE identity")
            continue

        required = {"pack.json", "rules-exec.yar"}
        if not required.issubset(files) or files - required - {
                "research.json", "reviewed-evidence.json"
        }:
            raise ReleaseRejected(
                f"{case.name}: expected pack.json, rules-exec.yar and optional review artifacts"
            )
        pack_path = case / "pack.json"
        rule_path = case / "rules-exec.yar"
        if any(path.stat().st_size > 1 << 20
               for path in (pack_path, rule_path)):
            raise ReleaseRejected(f"{case.name}: oversized source file")
        try:
            pack = json.loads(pack_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ReleaseRejected(f"{case.name}: invalid pack JSON") from exc
        if not isinstance(pack, dict) or pack.get("cve") != case.name:
            raise ReleaseRejected(f"{case.name}: pack CVE identifier mismatch")
        validate_source_pack(pack, rule_path, packfile=pack_path)
        for record in pack["records"]:
            record_id = record["record_id"]
            if record_id in record_ids:
                raise ReleaseRejected(
                    f"{case.name}: duplicate global record ID {record_id}")
            record_ids.add(record_id)

        if "reviewed-evidence.json" not in files:
            continue
        evidence_path = case / "reviewed-evidence.json"
        if evidence_path.stat().st_size > 16 << 20:
            raise ReleaseRejected(f"{case.name}: oversized review artifact")
        try:
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ReleaseRejected(
                f"{case.name}: invalid review artifact") from exc
        if (not isinstance(evidence, dict) or
                evidence.get("schema_version") != 3 or
                evidence.get("cve") != case.name or
                evidence.get("pack_sha256") != sha256(pack_path) or
                evidence.get("rules_sha256") != sha256(rule_path) or
                not isinstance(evidence.get("samples"), list) or
                not evidence["samples"] or
                not evidence.get("training_lineages")):
            raise ReleaseRejected(
                f"{case.name}: review artifact does not bind this CVE source")
        reviewed_cves.append(case.name)
    return reviewed_cves


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        reviewed = check(args.root)
    except (ReleaseRejected, OSError) as exc:
        parser.exit(2, f"SIGNATURE TREE REJECTED: {exc}\n")
    print(
        f"CVE source tree valid; independently reviewed CVEs: {len(reviewed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
