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
from scripts.check_validated_signatures import check
from tools.production_db import ReleaseRejected, build_release, verify_release

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[a-f0-9]{64}\Z")


def run(root: Path, scanner: Path, approved_host: str) -> dict:
    cves = check(root)
    if not cves:
        return {"status": "EMPTY_SOURCE_TREE", "cve_count": 0}
    try:
        lock = json.loads(
            (root / "release" / "reviewed-corpus.lock.json").read_text())
    except (OSError, ValueError) as exc:
        raise ReleaseRejected(
            "validated CVEs require a reviewed corpus lock") from exc
    url = lock.get("archive_url")
    digest = lock.get("archive_sha256")
    if (lock.get("schema_version") != 2 or not isinstance(url, str) or
            not isinstance(digest, str) or not SHA.fullmatch(digest)):
        raise ReleaseRejected(
            "validated CVEs require immutable HTTPS corpus URL and SHA")
    if not approved_host:
        raise ReleaseRejected(
            "reviewed corpus host must be configured by repository admins")
    with tempfile.TemporaryDirectory(
            prefix="vulnimprint-native-admission-") as temp:
        work = Path(temp)
        artifact_dir = work / "download"
        artifact_dir.mkdir()
        from scripts.fetch_reviewed_corpus import fetch
        archive = artifact_dir / "reviewed_cases.tar.gz"
        try:
            fetch(url, digest, approved_host, archive)
        except (OSError, ValueError) as exc:
            raise ReleaseRejected("cannot download verified corpus") from exc
        extracted = work / "cases"
        try:
            unpack(archive, digest, extracted)
        except (OSError, ValueError, tarfile.TarError) as exc:
            raise ReleaseRejected('reviewed corpus integrity failed') from exc
        out = work / "database"
        build_release(extracted,
                      out,
                      scanner,
                      min_cves=len(cves),
                      signatures=root / "signatures" / "validated")
        verify_release(out, scanner=scanner)
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
