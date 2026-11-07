"""Canonical CVE and database-record identities."""

from __future__ import annotations

import hashlib
import json
import re

_CVE = re.compile(r"CVE-\d{4}-\d{4,}\Z")
_RECORD = re.compile(r"VI_[A-F0-9]{24}\Z")
CHANNELS = frozenset({"test", "production"})
PACK_KEYS = frozenset({"schema_version", "cve", "records", "notes"})
RECORD_KEYS = frozenset({
    "record_id",
    "channel",
    "source_type",
    "platform",
    "supported_profiles",
    "rules",
    "scope",
    "hints",
    "notes",
})


def new_record_id(cve: str, record_key: str = "default") -> str:
    """Return a stable CVE-owned record ID.

    The default key produces a stable identifier for the primary record.
    Additional records must use a stable, non-empty record_key.
    """
    if not isinstance(cve, str) or not _CVE.fullmatch(cve):
        raise ValueError("invalid CVE identifier")
    if (not isinstance(record_key, str) or not record_key or
            len(record_key) > 128 or
            not re.fullmatch(r"[A-Za-z0-9_.-]+", record_key)):
        raise ValueError("invalid record key")
    material = cve.encode("ascii")
    if record_key != "default":
        material += b"\x00" + record_key.encode("ascii")
    return "VI_" + hashlib.sha256(material).hexdigest()[:24].upper()


def record_identity(cve: str, record: dict) -> tuple[str, str]:
    """Validate a record and return its unique ID and owning CVE."""
    if not isinstance(cve, str) or not _CVE.fullmatch(cve):
        raise ValueError("invalid CVE identifier")
    if not isinstance(record, dict):
        raise ValueError("database record must be an object")
    if set(record) - RECORD_KEYS:
        raise ValueError("database record contains unsupported fields")
    record_id = record.get("record_id")
    if not isinstance(record_id, str) or not _RECORD.fullmatch(record_id):
        raise ValueError("database record requires a stable VI_ record_id")
    if record.get("channel") not in CHANNELS:
        raise ValueError("database record channel must be test or production")
    return record_id, cve


def cve_pack_records(pack: dict) -> list[dict]:
    """Validate the CVE-level envelope and return its database records."""
    cve = pack.get("cve") if isinstance(pack, dict) else None
    if not isinstance(cve, str) or not _CVE.fullmatch(cve):
        raise ValueError("invalid CVE pack identifier")
    if set(pack) - PACK_KEYS:
        raise ValueError("CVE pack contains unsupported fields")
    if pack.get("schema_version") != 3:
        raise ValueError(f"{cve}: unsupported CVE pack schema")
    records = pack.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError(f"{cve}: CVE pack must contain database records")
    seen = set()
    for record in records:
        record_id, _ = record_identity(cve, record)
        if record_id in seen:
            raise ValueError(f"{cve}: duplicate record_id {record_id}")
        seen.add(record_id)
    return records


def record_sha256(record: dict) -> str:
    """Hash one canonical record independently of its containing CVE pack."""
    if not isinstance(record, dict):
        raise ValueError("database record must be an object")
    payload = json.dumps(record,
                         sort_keys=True,
                         separators=(",", ":"),
                         ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
