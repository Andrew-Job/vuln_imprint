#!/usr/bin/env python3
"""Check the retained libpng CVE records against original machine anchors.

This verifies source consistency only. It does not assert that any pattern is
an accurate detector; native YARA-X and independent CVE analysis are separate.
"""
from __future__ import annotations

import json
from pathlib import Path

from factory.patterns import Pattern
from factory.yara_engine import source_from_packs
from tools.manual_rules import check_manual_source

ROOT = Path(__file__).resolve().parents[1]
RESEARCH_DOSSIER = ROOT / "docs/research/libpng-elf64-x86_64"
SIGNATURES = ROOT / "signatures"
CVES = (
    "CVE-2026-22695",
    "CVE-2026-22801",
    "CVE-2026-25646",
    "CVE-2026-33416",
    "CVE-2026-34757",
)


def check() -> dict:
    actual = tuple(
        sorted(path.name
               for path in SIGNATURES.glob("CVE-*")
               if path.is_dir() and (path / "pack.json").is_file()))
    if not set(CVES).issubset(actual):
        raise ValueError("baseline libpng CVE source is missing")
    packs = []
    for cve in CVES:
        folder = SIGNATURES / cve
        pack = json.loads((folder / "pack.json").read_text(encoding="utf-8"))
        if pack.get("cve") != cve or pack.get("schema_version") != 3:
            raise ValueError(f"{cve}: CVE pack identity/schema mismatch")
        if not pack.get("records"):
            raise ValueError(f"{cve}: no database records")
        for record in pack["records"]:
            if (record.get("channel") != "production" or
                    record.get("source_type") != "manual"):
                raise ValueError(f"{cve}: expected production manual record")
        check_manual_source(
            pack, (folder / "rules-exec.yar").read_text(encoding="utf-8"))
        packs.append(pack)
    pattern_count = sum(
        len(record["rules"]) for pack in packs for record in pack["records"])
    if pattern_count != 25:
        raise ValueError("baseline libpng machine patterns have changed")
    if (RESEARCH_DOSSIER / "database-exec.yar").read_text(
            encoding="utf-8") != source_from_packs(packs):
        raise ValueError("combined CVE source does not match checked records")

    anchors = json.loads(
        (RESEARCH_DOSSIER / "machine-anchors.json").read_text(encoding="utf-8"))
    if set(anchors) != {"CVE-2026-33416", "CVE-2026-34757"}:
        raise ValueError("expected bytecode anchor sets are missing")
    anchor_count = 0
    for cve, rows in anchors.items():
        reviewed_masks = {
            item["hex"] for pack in packs if pack["cve"] == cve
            for record in pack["records"]
            for item in record["rules"]
        }
        if len(rows) != len(reviewed_masks):
            raise ValueError(f"{cve}: machine anchor count mismatch")
        for row in rows:
            if row["hex"] not in reviewed_masks:
                raise ValueError(f"{cve}: unknown machine anchor")
            pattern = Pattern.from_hex(row["hex"])
            original = bytes.fromhex(row["raw_bytes"])
            if (len(original) != row["bytes"] or
                    len(pattern.data) != len(original) or
                    pattern.fixed != row["fixed_bytes"] or pattern.fixed < 24 or
                    not pattern.matches_at(original, 0)):
                raise ValueError(f"{cve}: machine anchor does not match rule")
            first_fixed = pattern.mask.index(255)
            tampered = bytearray(original)
            tampered[first_fixed] ^= 255
            if pattern.matches_at(tampered, 0):
                raise ValueError(f"{cve}: fixed byte incorrectly ignored")
            anchor_count += 1
    if anchor_count != 15:
        raise ValueError("incomplete original bytecode anchor set")
    matrix = json.loads((RESEARCH_DOSSIER /
                         "validation-matrix.json").read_text(encoding="utf-8"))
    if (matrix.get("native_yara_x_checked") is not False or
        {case["cve"] for case in matrix.get("cases", [])} != set(CVES)):
        raise ValueError(
            "research matrix no longer describes the checked source set")
    for case in matrix["cases"]:
        if "channel" in case and case["channel"] != "production":
            raise ValueError(
                "research matrix channel differs from source records")
    return {
        "status":
            "PASS",
        "channel":
            "production",
        "cve_count":
            len(packs),
        "record_count":
            sum(len(pack["records"]) for pack in packs),
        "patterns":
            pattern_count,
        "original_machine_anchors_checked":
            anchor_count,
        "native_yara_x":
            "NOT_RUN",
        "interpretation":
            ("Source consistency only; detector correctness is not established."
            ),
    }


def main() -> int:
    try:
        print(json.dumps(check(), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"CVE SOURCE CHECK FAILED: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
