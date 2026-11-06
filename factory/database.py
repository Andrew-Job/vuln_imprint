"""Build deterministic channel-specific snapshots from CVE-owned records."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .signature_identity import cve_pack_records, record_identity, record_sha256
from .yara_engine import source_from_packs


def _platform_key(platform: dict) -> str:
    if not isinstance(platform, dict):
        raise ValueError("invalid platform metadata")
    return json.dumps(platform,
                      sort_keys=True,
                      separators=(",", ":"),
                      allow_nan=False)


def _records_for_channel(pack: dict, channel: str) -> list[dict]:
    records = cve_pack_records(pack)
    if channel == "production":
        return [
            record for record in records if record["channel"] == "production"
        ]
    if channel == "test":
        # Test snapshots are a superset: production records remain regression
        # coverage while test-only records are added for experimentation.
        return records
    raise ValueError("database channel must be test or production")


def merge_packs(pack_dirs: list[Path], output: Path, channel: str = "test"):
    """Merge CVE packs into a test or production snapshot.

    A production snapshot contains only production records. A test snapshot
    contains both test and production records. Reusing identical byte patterns
    across CVEs is intentional; record IDs remain globally unique.
    """
    if channel not in ("test", "production"):
        raise ValueError("database channel must be test or production")
    output.mkdir(parents=True, exist_ok=True)
    index, seen = [], set()
    database_sources = []
    for directory in sorted(map(Path, pack_dirs)):
        pack_file = directory / "pack.json"
        if not pack_file.is_file():
            continue
        pack = json.loads(pack_file.read_text(encoding="utf-8"))
        records = _records_for_channel(pack, channel)
        for record in sorted(records, key=lambda row: row["record_id"]):
            record_id, cve = record_identity(pack["cve"], record)
            if record_id in seen:
                raise ValueError(f"duplicate database record ID: {record_id}")
            seen.add(record_id)
            platform = record.get("platform", {})
            profile_key = _platform_key(platform)
            filtered = {**pack, "records": [record]}
            source = source_from_packs([filtered])
            if not source.strip():
                continue
            database_sources.append(source.rstrip())
            digest = hashlib.sha256(profile_key.encode()).hexdigest()[:20]
            dest_name = f"{record_id}-{digest}"
            dest = output / "packs" / dest_name
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "pack.json").write_text(json.dumps(
                filtered, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
                                            encoding="utf-8")
            (dest / "rules-exec.yar").write_text(source, encoding="utf-8")
            index.append({
                "cve": cve,
                "record_id": record_id,
                "record_sha256": record_sha256(record),
                "channel": record["channel"],
                "platform": platform,
                "pattern_count": len(record["rules"]),
                "included": True,
                "pack_dir": (Path("packs") / dest_name).as_posix(),
            })
    (output / "database.yar").write_text("\n".join(database_sources) +
                                         ("\n" if database_sources else ""),
                                         encoding="utf-8")
    included_cves = sorted({entry["cve"] for entry in index})
    report = {
        "schema_version": 2,
        "channel": channel,
        "cve_count": len(included_cves),
        "record_count": len(index),
        "pattern_count": sum(entry["pattern_count"] for entry in index),
        "entries": index,
    }
    (output / "index.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report


def load_included_packs(directory: Path):
    """Load snapshot records while validating index paths and identities."""
    root = Path(directory).resolve()
    index = json.loads((root / "index.json").read_text(encoding="utf-8"))
    if (index.get("schema_version") != 2 or
            index.get("channel") not in ("test", "production")):
        raise ValueError("unsupported database snapshot index or channel")
    result, seen = [], set()
    pattern_total = 0
    for entry in index.get("entries", []):
        if not entry.get("included"):
            continue
        folder = entry.get("pack_dir")
        if not isinstance(folder, str) or not folder:
            raise ValueError("index entry lacks pack_dir")
        relative = Path(folder)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsafe pack_dir in database index")
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_dir():
            raise ValueError("pack_dir escapes database snapshot or is missing")
        pack = json.loads((path / "pack.json").read_text(encoding="utf-8"))
        records = cve_pack_records(pack)
        if len(records) != 1:
            raise ValueError("snapshot pack must contain exactly one record")
        record = records[0]
        record_id, cve = record_identity(pack["cve"], record)
        if (entry.get("cve") != cve or entry.get("record_id") != record_id or
                entry.get("record_sha256") != record_sha256(record) or
            (index["channel"] == "production" and
             record.get("channel") != "production") or
                entry.get("channel") != record.get("channel") or
                entry.get("platform") != record.get("platform") or
                entry.get("pattern_count") != len(record.get("rules", [])) or
                record_id in seen):
            raise ValueError(
                "database index CVE/record identity is inconsistent")
        seen.add(record_id)
        pattern_total += len(record.get("rules", []))
        result.append(pack)
    if len(result) != index.get("record_count"):
        raise ValueError("database index record count is inconsistent")
    if pattern_total != index.get("pattern_count"):
        raise ValueError("database index pattern count is inconsistent")
    if len({pack["cve"] for pack in result}) != index.get("cve_count"):
        raise ValueError("database index CVE count is inconsistent")
    return result
