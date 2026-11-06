#!/usr/bin/env python3
"""Validate the version-controlled release source tree before merging.

Only signatures/validated/ is the source of production CVE rules.
Experimental material under signatures/candidates/ is excluded from releases;
source-only checks do not substitute for native reviewed-corpus admission.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from tools.production_db import (
    HASH,
    CVE,
    ReleaseRejected,
    sha256,
    validate_source_pack,
)

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {"pack.json", "rules-exec.yar", "reviewed-evidence.json"}
RESEARCH = ("research", "cve_queue", "catalog_recent", "catalog", "signatures/staging")


def check(root: Path = ROOT) -> list[str]:
    """Return the exact, sorted CVE set that will be published from Git."""
    for name in RESEARCH:
        location = root / name
        if location.exists():
            raise ReleaseRejected(f"unvalidated research in release tree: {name}")
    signatures = root / "signatures" / "validated"
    if not signatures.is_dir() or signatures.is_symlink():
        raise ReleaseRejected("validated Git signature directory is missing")

    cves = []
    for case in sorted(signatures.iterdir()):
        if case.name == ".gitkeep" and case.is_file():
            continue
        if case.is_symlink() or not case.is_dir() or not CVE.fullmatch(case.name):
            raise ReleaseRejected(f"unexpected entry in validated signatures: {case.name}")
        files = {p.name for p in case.iterdir()}
        if files != REQUIRED or any((case / name).is_symlink() for name in files):
            raise ReleaseRejected(f"{case.name}: exactly three canonical source files required")
        pack_path = case / "pack.json"
        source = case / "rules-exec.yar"
        evidence_path = case / "reviewed-evidence.json"
        for path in (pack_path, source, evidence_path):
            if path.stat().st_size > 1 << 20:
                raise ReleaseRejected(f"{case.name}: oversized source file")
        try:
            pack = json.loads(pack_path.read_text(encoding="utf-8"))
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ReleaseRejected(f"{case.name}: invalid metadata JSON") from exc
        if not isinstance(pack, dict) or not isinstance(evidence, dict):
            raise ReleaseRejected(f"{case.name}: metadata must be JSON objects")
        if pack.get("cve") != case.name:
            raise ReleaseRejected(f"{case.name}: pack CVE identifier mismatch")
        validate_source_pack(pack, source, packfile=pack_path)
        if (pack.get("status") != "CVE_SPECIFIC_VALIDATED"
                or evidence.get("schema_version") != 2
                or evidence.get("quality") != "CVE_SPECIFIC_VALIDATED"
                or evidence.get("cve") != case.name):
            raise ReleaseRejected(f"{case.name}: unapproved CVE state")
        if (evidence.get("rules_sha256") != sha256(source)
                or evidence.get("pack_sha256") != sha256(pack_path)):
            raise ReleaseRejected(f"{case.name}: reviewed evidence digests are stale")
        if not isinstance(evidence.get("samples"), list) or not evidence["samples"]:
            raise ReleaseRejected(f"{case.name}: independent reviewed samples missing")
        if not evidence.get("training_lineages"):
            raise ReleaseRejected(f"{case.name}: training lineage missing")
        cves.append(case.name)
    return cves


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        cves = check(args.root)
    except (ReleaseRejected, OSError) as exc:
        parser.exit(2, f"SIGNATURE TREE REJECTED: {exc}\n")
    print(f"Validated Git CVEs: {len(cves)}" + (f" ({', '.join(cves)})" if cves else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
