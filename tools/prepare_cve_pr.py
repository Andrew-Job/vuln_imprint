#!/usr/bin/env python3
"""Prepare one or more CVE-owned DB records for a contributor branch.

This tool performs structural and native YARA-X compilation checks only. It
does not claim that a record is a correct CVE detector; correctness is reviewed
in separate research and validation work.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from factory.signature_identity import cve_pack_records
from factory.yara_engine import source_from_packs
from scripts.check_cve_source_tree import check
from tools.production_db import ReleaseRejected, sha256, validate_source_pack


def prepare(case: Path, scanner: Path, repo: Path) -> dict:
    case, scanner = Path(case), Path(scanner)
    repo = Path(repo).resolve()
    if case.is_symlink() or not case.is_dir():
        raise ReleaseRejected("case directory must be a real directory")
    if not scanner.is_file() or not scanner.stat().st_mode & 0o111:
        raise ReleaseRejected("an executable native YARA-X scanner is required")
    for name in ("pack.json", "rules-exec.yar"):
        source = case / name
        if source.is_symlink() or not source.is_file():
            raise ReleaseRejected(f"missing or symlinked case input: {name}")
    incoming = json.loads((case / "pack.json").read_text(encoding="utf-8"))
    cve = incoming.get("cve")
    if not isinstance(cve, str) or case.name != cve:
        raise ReleaseRejected("case directory and pack CVE must match")
    validate_source_pack(incoming,
                         case / "rules-exec.yar",
                         packfile=case / "pack.json")
    incoming_records = cve_pack_records(incoming)
    incoming_ids = {record["record_id"] for record in incoming_records}

    # Compile the exact incoming source with the real native C++ YARA-X engine.
    with tempfile.TemporaryDirectory(prefix="vulnimprint-pr-record-") as temp:
        compiled = Path(temp) / "records.yarc"
        process = subprocess.run([
            str(scanner), "compile", "--rules",
            str(case / "rules-exec.yar"), "--output",
            str(compiled)
        ],
                                 capture_output=True,
                                 text=True,
                                 timeout=120)
        if process.returncode or not compiled.is_file() or not compiled.stat(
        ).st_size:
            raise ReleaseRejected(
                f"native YARA-X compilation failed: {process.stderr[:600]}")

    check(repo)
    signatures = repo / "signatures"
    target = signatures / cve
    existed = target.exists()
    if existed and (target.is_symlink() or not target.is_dir()):
        raise ReleaseRejected("canonical CVE target is not a real directory")
    existing_pack_path = target / "pack.json"
    existing_rules_path = target / "rules-exec.yar"
    if existed and existing_pack_path.exists():
        existing = json.loads(existing_pack_path.read_text(encoding="utf-8"))
        existing_records = cve_pack_records(existing)
        old_ids = {record["record_id"] for record in existing_records}
        if old_ids & incoming_ids:
            raise ReleaseRejected(
                f"{cve}: record IDs already exist: {sorted(old_ids & incoming_ids)}"
            )
        combined = {
            **existing, "records":
                sorted([*existing_records, *incoming_records],
                       key=lambda record: record["record_id"])
        }
    else:
        combined = incoming
    combined_source = source_from_packs([combined])

    target.mkdir(parents=True, exist_ok=True)
    old_pack = existing_pack_path.read_bytes() if existing_pack_path.is_file(
    ) else None
    old_rules = existing_rules_path.read_bytes() if existing_rules_path.is_file(
    ) else None
    try:
        (target / "pack.json").write_text(
            json.dumps(combined, sort_keys=True, indent=2, ensure_ascii=False) +
            "\n",
            encoding="utf-8")
        (target / "rules-exec.yar").write_text(combined_source,
                                               encoding="utf-8")
        # Recheck the merged CVE envelope and ensure IDs remain globally unique.
        validate_source_pack(combined,
                             existing_rules_path,
                             packfile=existing_pack_path)
        check(repo)
    except BaseException:
        if old_pack is None:
            existing_pack_path.unlink(missing_ok=True)
        else:
            existing_pack_path.write_bytes(old_pack)
        if old_rules is None:
            existing_rules_path.unlink(missing_ok=True)
        else:
            existing_rules_path.write_bytes(old_rules)
        if not existed and target.exists() and not any(target.iterdir()):
            target.rmdir()
        raise
    return {
        "status":
            "READY_FOR_REVIEW",
        "cve":
            cve,
        "added_record_ids":
            sorted(incoming_ids),
        "record_count":
            len(combined["records"]),
        "channels":
            sorted({record["channel"] for record in combined["records"]}),
        "pack_sha256":
            sha256(existing_pack_path),
        "rules_sha256":
            sha256(existing_rules_path),
        "canonical_directory":
            str(target),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case",
                        type=Path,
                        required=True,
                        help="CVE pack with one or more CVE-owned DB records")
    parser.add_argument("--scanner",
                        type=Path,
                        required=True,
                        help="real C++ VulnImprint/YARA-X executable")
    parser.add_argument("--repo",
                        type=Path,
                        default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        print(
            json.dumps(prepare(args.case, args.scanner, args.repo),
                       indent=2,
                       sort_keys=True))
    except (ReleaseRejected, OSError, ValueError, TypeError, KeyError,
            subprocess.TimeoutExpired) as exc:
        parser.exit(2, f"CVE PREPARATION REJECTED: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
