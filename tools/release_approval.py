#!/usr/bin/env python3
"""Lock and verify the complete CVE composition of a public release.

The file produced here is an unsigned *statement* of release contents. The
privileged GitHub publish job cryptographically attests these exact bytes and
all shipped artifacts using OIDC/Sigstore; no long-lived private key is used.
"""

from __future__ import annotations

import argparse
import hashlib
import tarfile
import json
import re
import sys
from pathlib import Path

from tools.production_db import ReleaseRejected, sha256, verify_release

_CVE = re.compile(r"CVE-\d{4}-\d{4,}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_COMMIT = re.compile(r"[a-f0-9]{40}\Z")
_TAG = re.compile(r"v\d+\.\d+\.\d+\Z")
_PROFILE = "linux-elf64-x86_64-sysv"
_PRODUCT_ASSET = "vulnimprint-linux-x86_64.tar.gz"
_RELEASE_ASSETS = {_PRODUCT_ASSET, "SBOM.spdx.json"}
_DB_PREFIX = "vulnimprint/share/vulnimprint/db/"
_DB_MEMBERS = {
    "manifest.json", "index.json", "quality-report.json", "database.yar",
    "database.yarc", "SHA256SUMS"
}


def _load_json(path: Path) -> dict:
    """Read a bounded JSON document under first-party release control."""
    try:
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ReleaseRejected("release metadata exceeds size limit")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReleaseRejected(f"invalid release metadata: {path}") from exc
    if not isinstance(data, dict):
        raise ReleaseRejected("release metadata must be an object")
    return data


def _validate_entries(index: dict) -> list[dict]:
    """Return a deterministic, complete list of CVE rules and their digests."""
    entries = index.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ReleaseRejected("release requires validated CVE entries")
    if len(entries) != index.get("cve_count"):
        raise ReleaseRejected("release index and CVE entry count differ")
    result = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReleaseRejected("malformed CVE release entry")
        cve = entry.get("cve")
        if not isinstance(cve, str) or not _CVE.fullmatch(cve) or cve in seen:
            raise ReleaseRejected("invalid or repeated release CVE")
        seen.add(cve)
        if entry.get("quality") != "CVE_SPECIFIC_VALIDATED":
            raise ReleaseRejected("release contains nonproduction CVE")
        hashes = {}
        for field in ("pack_sha256", "rules_sha256"):
            digest = entry.get(field)
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise ReleaseRejected("release CVE missing provenance digest")
            hashes[field] = digest
        result.append({
            "cve": cve,
            "quality": "CVE_SPECIFIC_VALIDATED",
            **hashes,
        })
    return sorted(result, key=lambda item: item["cve"])


def make_contents(database: Path, tag: str, source_commit: str,
                  assets: list[Path]) -> dict:
    """Bind validated CVEs and distributed assets in a single statement."""
    if not _TAG.fullmatch(tag) or not _COMMIT.fullmatch(source_commit):
        raise ReleaseRejected("invalid release tag or source SHA")
    verify_release(database)
    index = _load_json(database / "index.json")
    db_manifest = _load_json(database / "manifest.json")
    if db_manifest.get("cve_count") != index.get("cve_count"):
        raise ReleaseRejected("database manifest and index disagree")
    if not assets:
        raise ReleaseRejected("release has no downloadable assets")
    named_assets = {}
    for asset in assets:
        if (asset.name in named_assets or not asset.is_file() or
                asset.is_symlink() or asset.name.startswith(".") or
                "/" in asset.name or asset.stat().st_size == 0):
            raise ReleaseRejected("invalid or duplicate release asset")
        named_assets[asset.name] = sha256(asset)
    if set(named_assets) != _RELEASE_ASSETS:
        raise ReleaseRejected("missing or unexpected release assets")
    return {
        "schema_version": 1,
        "product": "VulnImprint",
        "release_tag": tag,
        "source_commit": source_commit,
        "platform_profile": _PROFILE,
        "database_index_sha256": sha256(database / "index.json"),
        "database_manifest_sha256": sha256(database / "manifest.json"),
        "cve_count": index["cve_count"],
        "cves": _validate_entries(index),
        "artifacts": dict(sorted(named_assets.items())),
    }


def verify_contents(contents: Path, assets_dir: Path) -> dict:
    """Validate the exact unsigned statement that CI signs separately."""
    statement = _load_json(contents)
    if statement.get("schema_version") != 1:
        raise ReleaseRejected("unsupported release-contents schema")
    if (statement.get("product") != "VulnImprint" or
            statement.get("platform_profile") != _PROFILE or
            not isinstance(statement.get("release_tag"), str) or
            not _TAG.fullmatch(statement["release_tag"]) or
            not isinstance(statement.get("source_commit"), str) or
            not _COMMIT.fullmatch(statement["source_commit"])):
        raise ReleaseRejected("invalid release identity")
    for field in ("database_index_sha256", "database_manifest_sha256"):
        if (not isinstance(statement.get(field), str) or
                not _SHA256.fullmatch(statement[field])):
            raise ReleaseRejected("invalid database binding")
    entries = _validate_entries({
        "entries": statement.get("cves"),
        "cve_count": statement.get("cve_count"),
    })
    if entries != statement["cves"]:
        raise ReleaseRejected("release CVE list must be sorted")
    assets = statement.get("artifacts")
    if not isinstance(assets, dict) or not assets:
        raise ReleaseRejected("empty release artifact set")
    if set(assets) != _RELEASE_ASSETS:
        raise ReleaseRejected("release artifacts differ from supported profile")
    for name, expected in assets.items():
        if (not isinstance(name, str) or
                not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or
                name.startswith(".") or not isinstance(expected, str) or
                not _SHA256.fullmatch(expected)):
            raise ReleaseRejected("invalid signed artifact entry")
        asset = assets_dir / name
        if (not asset.is_file() or asset.is_symlink() or
                sha256(asset) != expected):
            raise ReleaseRejected(f"release artifact digest mismatch: {name}")
    # Bind the exact compiled database inside the one shipped application.
    product = assets_dir / _PRODUCT_ASSET
    try:
        with tarfile.open(product, "r:gz") as archive:
            members = archive.getmembers()
            if len(members) > 10000:
                raise ReleaseRejected("oversized application member table")
            contained = {}
            for member in members:
                if not member.name.startswith(_DB_PREFIX):
                    continue
                name = member.name[len(_DB_PREFIX):]
                if not name or name.endswith("/"):
                    continue
                if (name not in _DB_MEMBERS or name in contained or
                        not member.isfile() or member.size > 512 * 1024 * 1024):
                    raise ReleaseRejected("invalid embedded DB archive entry")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ReleaseRejected("unreadable packaged database entry")
                with stream:
                    contained[name] = stream.read(member.size + 1)
                if len(contained[name]) != member.size:
                    raise ReleaseRejected("truncated embedded DB archive entry")
            if set(contained) != _DB_MEMBERS:
                raise ReleaseRejected("incomplete embedded production database")
    except (OSError, tarfile.TarError) as exc:
        raise ReleaseRejected("invalid product archive") from exc
    digest = lambda data: hashlib.sha256(data).hexdigest()
    if (digest(contained["index.json"]) != statement["database_index_sha256"] or
            digest(contained["manifest.json"])
            != statement["database_manifest_sha256"]):
        raise ReleaseRejected("release statement does not bind embedded DB")
    try:
        index = json.loads(contained["index.json"])
        manifest = json.loads(contained["manifest.json"])
    except ValueError as exc:
        raise ReleaseRejected("invalid embedded DB metadata") from exc
    if _validate_entries(index) != entries or manifest.get(
            "schema_version") != 2:
        raise ReleaseRejected("embedded CVE set or database schema differs")
    digests = manifest.get("artifacts")
    if (not isinstance(digests, dict) or
            set(digests) != _DB_MEMBERS - {"manifest.json", "SHA256SUMS"}):
        raise ReleaseRejected("invalid embedded database manifest")
    for name, expected in digests.items():
        if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
            raise ReleaseRejected("invalid database digest")
        if digest(contained[name]) != expected:
            raise ReleaseRejected("embedded database digest mismatch")
    checksums = "".join(
        f"{value}  {name}\n" for name, value in sorted(digests.items()))
    if contained["SHA256SUMS"] != checksums.encode("utf-8"):
        raise ReleaseRejected(
            "embedded SHA256SUMS differs from database manifest")
    return {"status": "PASS", "cve_count": len(entries)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--database", type=Path, required=True)
    create.add_argument("--tag", required=True)
    create.add_argument("--source-commit", required=True)
    create.add_argument("--asset", type=Path, action="append", required=True)
    create.add_argument("--output", type=Path, required=True)
    check = sub.add_parser("verify")
    check.add_argument("--contents", type=Path, required=True)
    check.add_argument("--assets-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result = make_contents(args.database, args.tag, args.source_commit,
                                   args.asset)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(result, sort_keys=True, indent=2) + "\n",
                encoding="utf-8")
            print(
                json.dumps({
                    "status": "PASS",
                    "cve_count": result["cve_count"]
                }))
        else:
            print(json.dumps(verify_contents(args.contents, args.assets_dir)))
        return 0
    except (ReleaseRejected, OSError) as exc:
        print(f"RELEASE BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
