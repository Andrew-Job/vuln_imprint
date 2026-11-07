"""Production YARA-X adapter: compile and scan CVE-owned database records."""
from __future__ import annotations

import hashlib
import importlib
import re
from pathlib import Path

from .signature_identity import (SUPPORTED_PLATFORM, cve_pack_records,
                                 record_identity)


def _file_sha256(path: Path) -> str:
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _load_yara_x():
    """Load the pinned upstream binding; never silently fall back to mocks."""
    try:
        return importlib.import_module("yara_x")
    except ModuleNotFoundError as exc:
        if exc.name != "yara_x":
            raise
        raise RuntimeError(
            "YARA-X is required: build Python binding from pinned source with "
            "scripts/build_yarax_python.sh") from exc


_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}\Z")
_RECORD_ID = re.compile(r"VI_[A-F0-9]{24}\Z")
_HEX_BYTES = re.compile(
    r"(?:[0-9A-Fa-f]{2}|\?\?)(?:\s+(?:[0-9A-Fa-f]{2}|\?\?))*\Z")


def source_from_packs(packs: list[dict], *, channels=None) -> str:
    """Render deterministic YARA rules; each record belongs to one CVE only.

    ``channels=None`` renders every record. A production database includes only
    production records; a test database may include both channels.
    """
    selected_channels = None if channels is None else set(channels)
    if selected_channels is not None and not selected_channels.issubset(
        {"test", "production"}):
        raise ValueError("unsupported database channel")
    output = []
    seen = set()
    ordered = sorted(packs, key=lambda item: item.get("cve", ""))
    for pack in ordered:
        cve = pack.get("cve") if isinstance(pack, dict) else None
        if not isinstance(cve, str) or not _CVE_ID.fullmatch(cve):
            raise ValueError("invalid CVE identifier in rule source")
        records = cve_pack_records(pack)
        for record in sorted(records, key=lambda item: item["record_id"]):
            record_id, _ = record_identity(cve, record)
            if record_id in seen:
                raise ValueError(
                    f"duplicate database record identifier: {record_id}")
            seen.add(record_id)
            channel = record["channel"]
            if selected_channels is not None and channel not in selected_channels:
                continue
            platform = record.get("platform")
            if (not isinstance(platform, dict) or
                    set(platform) != {"os", "format", "arch", "bits", "abi"} or
                    type(platform.get("bits")) is not int or
                    tuple(platform[field] for field in
                          ("os", "format", "arch", "bits", "abi")) !=
                    SUPPORTED_PLATFORM):
                raise ValueError(
                    f"{cve}/{record_id}: unsupported ELF platform")
            patterns = record.get("rules")
            if not isinstance(patterns, list) or not patterns:
                raise ValueError(f"{cve}/{record_id}: empty pattern collection")
            normalized = []
            for rule in patterns:
                pattern = rule.get("hex") if isinstance(rule, dict) else None
                if not isinstance(pattern,
                                  str) or not _HEX_BYTES.fullmatch(pattern):
                    raise ValueError(
                        f"{cve}/{record_id}: invalid hexadecimal pattern")
                normalized.append(" ".join(pattern.upper().split()))
            output.extend([
                f"rule {record_id} {{",
                "  meta:",
                f'    cve = "{cve}"',
                f'    channel = "{channel}"',
                "  strings:",
            ])
            for index, pattern in enumerate(normalized):
                output.append(f"    $v{index} = {{ {pattern} }}")
            output.extend(["  condition:", "    any of them", "}"])
    return "\n".join(output) + ("\n" if output else "")


class YaraXScanner:

    def __init__(self, rules):
        yara_x = _load_yara_x()
        self.yara_x = yara_x
        self.rules = rules
        self.scanner = yara_x.Scanner(rules)

    @classmethod
    def compile(cls, source: str):
        yara_x = _load_yara_x()
        return cls(yara_x.compile(source))

    @classmethod
    def load(cls, path: Path):
        yara_x = _load_yara_x()
        with Path(path).open("rb") as stream:
            return cls(yara_x.Rules.deserialize_from(stream))

    def save(self, path: Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with Path(path).open("wb") as stream:
            self.rules.serialize_into(stream)

    def scan(self, path: Path):
        from .elf import ELF
        elf = ELF(Path(path))
        findings = []
        for base, buf in elf.executable_ranges():
            result = self.scanner.scan(buf)
            for rule in result.matching_rules:
                for pattern in rule.patterns:
                    for match in pattern.matches:
                        metadata = dict(getattr(rule, "metadata", ()) or ())
                        cve = metadata.get("cve")
                        cve = (cve if isinstance(cve, str) and
                               _CVE_ID.fullmatch(cve) else None)
                        findings.append({
                            "cve": cve,
                            "record_id":
                                (str(rule.identifier) if cve and
                                 _RECORD_ID.fullmatch(str(rule.identifier)) else
                                 None),
                            "pattern": str(pattern.identifier),
                            "file_offset": base + int(match.offset),
                        })
        findings.sort(key=lambda item: (item["cve"] or "", item[
            "file_offset"], item["record_id"] or "", item["pattern"]))
        return {
            "target": str(path),
            "engine": "YARA-X/executable-ELF",
            "detected": bool(findings),
            "matches": findings,
        }


def compile_database(directory: Path):
    from .database import load_included_packs
    packs = load_included_packs(directory)
    source = source_from_packs(packs)
    target = Path(directory) / "database-exec.yar"
    target.write_text(source)
    scanner = YaraXScanner.compile(source)
    output = Path(directory) / "database.compiled"
    scanner.save(output)
    return {
        "record_count": sum(len(pack["records"]) for pack in packs),
        "cve_count": len({pack["cve"] for pack in packs}),
        "source": str(target),
        "compiled": str(output),
        "sha256": _file_sha256(output),
    }
