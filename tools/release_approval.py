#!/usr/bin/env python3
"""Lock and verify the CVE and database-record composition of a release."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path

from tools.production_db import ReleaseRejected, sha256, verify_release

_CVE = re.compile(r"CVE-\d{4}-\d{4,}\Z")
_RECORD = re.compile(r"VI_[A-F0-9]{24}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_COMMIT = re.compile(r"[a-f0-9]{40}\Z")
_TAG = re.compile(r"v\d+\.\d+\.\d+\Z")
_PROFILE = "linux-elf64-x86_64-sysv"
_PRODUCT_ASSET = "vulnimprint-linux-x86_64.tar.gz"
_RELEASE_ASSETS = {_PRODUCT_ASSET, "SBOM.spdx.json"}
_DB_PREFIX = "vulnimprint/share/vulnimprint/db/"
_DB_MEMBERS = {
    "manifest.json", "index.json", "database-report.json", "database.yar",
    "database.yarc", "SHA256SUMS"
}


def _load_json(path: Path) -> dict:
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
    """Group independently identified production records under their CVE."""
    if index.get("channel") != "production":
        raise ReleaseRejected("only a production database can be released")
    entries = index.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ReleaseRejected("release requires database records")
    grouped: dict[str, list[dict]] = {}
    seen_ids = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReleaseRejected("malformed database record entry")
        cve, record_id = entry.get("cve"), entry.get("record_id")
        if (not isinstance(cve, str) or not _CVE.fullmatch(cve) or
                not isinstance(record_id, str) or
                not _RECORD.fullmatch(record_id) or
                entry.get("channel") != "production"):
            raise ReleaseRejected("invalid production CVE/record identity")
        if record_id in seen_ids:
            raise ReleaseRejected("duplicate production record ID")
        seen_ids.add(record_id)
        record = {
            "record_id": record_id,
            "record_sha256": entry.get("record_sha256"),
            "channel": "production",
            "pattern_count": entry.get("pattern_count"),
        }
        if type(record["pattern_count"]
               ) is not int or record["pattern_count"] < 1:
            raise ReleaseRejected("invalid production record pattern count")
        for field in ("record_sha256", "pack_sha256", "rules_sha256"):
            digest = entry.get(field)
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise ReleaseRejected(
                    "production record lacks source provenance")
            record[field] = digest
        grouped.setdefault(cve, []).append(record)
    if len(grouped) != index.get("cve_count") or len(entries) != index.get(
            "record_count"):
        raise ReleaseRejected("release index and CVE/record counts differ")
    return [{
        "cve": cve,
        "records": sorted(records, key=lambda row: row["record_id"])
    } for cve, records in sorted(grouped.items())]


def _validate_statement(rows: object, cve_count: object,
                        record_count: object) -> list[dict]:
    if not isinstance(rows, list) or not rows or len(rows) != cve_count:
        raise ReleaseRejected("release CVE statement count is inconsistent")
    seen_cves, seen_records = set(), set()
    result = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"cve", "records"}:
            raise ReleaseRejected("malformed release CVE entry")
        cve = row["cve"]
        if not isinstance(cve,
                          str) or not _CVE.fullmatch(cve) or cve in seen_cves:
            raise ReleaseRejected("invalid or duplicate release CVE")
        seen_cves.add(cve)
        records = row["records"]
        if not isinstance(records, list) or not records:
            raise ReleaseRejected("release CVE has no production records")
        checked = []
        for record in records:
            required = {
                "record_id", "record_sha256", "channel", "pattern_count",
                "pack_sha256", "rules_sha256"
            }
            if not isinstance(record, dict) or set(record) != required:
                raise ReleaseRejected("malformed signed production record")
            record_id = record["record_id"]
            if (not isinstance(record_id, str) or
                    not _RECORD.fullmatch(record_id) or
                    record_id in seen_records or
                    record["channel"] != "production" or
                    type(record["pattern_count"]) is not int or
                    record["pattern_count"] < 1 or
                    any(not isinstance(record[field], str) or
                        not _SHA256.fullmatch(record[field])
                        for field in ("record_sha256", "pack_sha256",
                                      "rules_sha256"))):
                raise ReleaseRejected(
                    "invalid signed record identity or digest")
            seen_records.add(record_id)
            checked.append(record)
        if checked != sorted(checked, key=lambda item: item["record_id"]):
            raise ReleaseRejected("records must be sorted within each CVE")
        result.append(row)
    if result != sorted(result, key=lambda item: item["cve"]):
        raise ReleaseRejected("release CVEs must be sorted")
    if len(seen_records) != record_count:
        raise ReleaseRejected("release record count is inconsistent")
    return result


def make_contents(database: Path, tag: str, source_commit: str,
                  assets: list[Path]) -> dict:
    if not _TAG.fullmatch(tag) or not _COMMIT.fullmatch(source_commit):
        raise ReleaseRejected("invalid release tag or source SHA")
    verify_release(database)
    index = _load_json(database / "index.json")
    manifest = _load_json(database / "manifest.json")
    if (manifest.get("channel") != "production" or
            manifest.get("cve_count") != index.get("cve_count") or
            manifest.get("record_count") != index.get("record_count")):
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
        raise ReleaseRejected("missing or unexpected release asset")
    return {
        "schema_version": 2,
        "product": "VulnImprint",
        "release_tag": tag,
        "source_commit": source_commit,
        "platform_profile": _PROFILE,
        "database_index_sha256": sha256(database / "index.json"),
        "database_manifest_sha256": sha256(database / "manifest.json"),
        "cve_count": index["cve_count"],
        "record_count": index["record_count"],
        "cves": _validate_entries(index),
        "artifacts": dict(sorted(named_assets.items())),
    }


def verify_contents(contents: Path, assets_dir: Path) -> dict:
    statement = _load_json(contents)
    if statement.get("schema_version") != 2:
        raise ReleaseRejected("unsupported release-contents schema")
    if (statement.get("product") != "VulnImprint" or
            statement.get("platform_profile") != _PROFILE or
            not isinstance(statement.get("release_tag"), str) or
            not _TAG.fullmatch(statement["release_tag"]) or
            not isinstance(statement.get("source_commit"), str) or
            not _COMMIT.fullmatch(statement["source_commit"])):
        raise ReleaseRejected("invalid release identity")
    for field in ("database_index_sha256", "database_manifest_sha256"):
        if not isinstance(statement.get(field), str) or not _SHA256.fullmatch(
                statement[field]):
            raise ReleaseRejected("invalid database binding")
    entries = _validate_statement(statement.get("cves"),
                                  statement.get("cve_count"),
                                  statement.get("record_count"))
    assets = statement.get("artifacts")
    if not isinstance(assets, dict) or set(assets) != _RELEASE_ASSETS:
        raise ReleaseRejected("release artifacts differ from supported profile")
    for name, expected in assets.items():
        if (not isinstance(name, str) or
                not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or
                name.startswith(".") or not isinstance(expected, str) or
                not _SHA256.fullmatch(expected)):
            raise ReleaseRejected("invalid signed artifact entry")
        asset = assets_dir / name
        if not asset.is_file() or asset.is_symlink() or sha256(
                asset) != expected:
            raise ReleaseRejected(f"release artifact digest mismatch: {name}")

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
    if (_validate_entries(index) != entries or
            manifest.get("schema_version") != 3 or
            manifest.get("channel") != "production" or
            manifest.get("cve_count") != statement["cve_count"] or
            manifest.get("record_count") != statement["record_count"]):
        raise ReleaseRejected(
            "embedded CVE/record set or database schema differs")
    digests = manifest.get("artifacts")
    expected_names = _DB_MEMBERS - {"manifest.json", "SHA256SUMS"}
    if not isinstance(digests, dict) or set(digests) != expected_names:
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
    return {
        "status": "PASS",
        "cve_count": statement["cve_count"],
        "record_count": statement["record_count"]
    }


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
                    "cve_count": result["cve_count"],
                    "record_count": result["record_count"]
                }))
        else:
            print(json.dumps(verify_contents(args.contents, args.assets_dir)))
        return 0
    except (ReleaseRejected, OSError) as exc:
        print(f"RELEASE BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
