#!/usr/bin/env python3
"""Validate Git CVE rules on immutable, SHA-pinned independent specimens.

The reviewer-controlled HTTPS host must be configured in repository settings.
Candidate source files are never accepted from the downloaded corpus.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import tarfile
import tempfile
from pathlib import Path

from scripts.safe_unpack_corpus import unpack
from scripts.check_cve_source_tree import check
from tools.production_db import ReleaseRejected, review_cases

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[a-f0-9]{64}\Z")


def run(root: Path, scanner: Path, approved_host: str) -> dict:
    cves = check(root)
    if not cves:
        return {
            "status": "NO_REVIEWED_EVIDENCE",
            "reviewed_cve_count": 0,
            "cve_accuracy": "NOT_ESTABLISHED"
        }
    try:
        lock = json.loads(
            (root / "release" / "reviewed-corpus.lock.json").read_text())
    except (OSError, ValueError) as exc:
        raise ReleaseRejected(
            "validated CVEs require a reviewed corpus lock") from exc
    entries = lock.get("cases")
    if lock.get("schema_version") != 3 or not isinstance(entries, dict):
        raise ReleaseRejected(
            "reviewed corpus lock schema must be 3 with per-CVE cases")
    if not approved_host:
        raise ReleaseRejected(
            "reviewed corpus host must be configured by repository admins")
    if set(entries) != set(cves):
        raise ReleaseRejected(
            "corpus lock must bind exactly the reviewed Git CVEs")
    with tempfile.TemporaryDirectory(
            prefix="vulnimprint-native-admission-") as temp:
        work = Path(temp)
        cases = work / "cases"
        cases.mkdir()
        downloads = work / "downloads"
        downloads.mkdir()
        from scripts.fetch_reviewed_corpus import fetch
        for cve in cves:
            entry = entries[cve]
            if not isinstance(entry, dict) or set(entry) != {
                    "archive_url", "archive_sha256"
            }:
                raise ReleaseRejected(f"{cve}: invalid pinned case descriptor")
            url = entry["archive_url"]
            digest = entry["archive_sha256"]
            if (not isinstance(url, str) or not isinstance(digest, str) or
                    not SHA.fullmatch(digest)):
                raise ReleaseRejected(
                    f"{cve}: immutable HTTPS URL and SHA required")
            archive = downloads / f"{cve}.tar.gz"
            try:
                fetch(url, digest, approved_host, archive)
                # One archive contains one CVE case's canonical files and
                # immutable specimens, relative to that case's root.
                unpack(archive, digest, cases / cve)
            except (OSError, ValueError, tarfile.TarError) as exc:
                raise ReleaseRejected(
                    f"{cve}: independently reviewed corpus unavailable or invalid"
                ) from exc
        review_cases(cases,
                     scanner,
                     min_cves=len(cves),
                     signatures=root / "signatures")
    return {"status": "PASS", "cve_count": len(cves)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--approved-host",
                        default=os.environ.get("VULNIMPRINT_CORPUS_HOST", ""))
    args = parser.parse_args()
    try:
        print(
            json.dumps(run(ROOT, args.scanner, args.approved_host),
                       sort_keys=True))
    except (ReleaseRejected, OSError, ValueError) as exc:
        parser.exit(2, f"NATIVE ADMISSION REJECTED: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
