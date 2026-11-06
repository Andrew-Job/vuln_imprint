#!/usr/bin/env python3
"""Fail-closed offline validation of five libpng research CVE rule sources.

Checks YARA source determinism and original machine-code anchors. This is
NOT an independent native scanner result or production admission.
"""
from __future__ import annotations

import json
from pathlib import Path

from factory.patterns import Pattern
from factory.yara_engine import source_from_packs
from tools.manual_rules import check_manual_source

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = ROOT / "signatures/candidates/libpng-elf64-x86_64"
CVES = (
    "CVE-2026-22695",
    "CVE-2026-22801",
    "CVE-2026-25646",
    "CVE-2026-33416",
    "CVE-2026-34757",
)


def check() -> dict:
    actual = tuple(
        sorted(p.name for p in CANDIDATES.glob("CVE-*") if p.is_dir()))
    if actual != CVES:
        raise ValueError("Research CVE directory set has changed")
    packs = []
    for cve in CVES:
        folder = CANDIDATES / cve
        pack = json.loads((folder / "pack.json").read_text(encoding="utf-8"))
        if pack.get("cve") != cve or pack.get("status") != "CANDIDATE_ONLY":
            raise ValueError(f"{cve}: research-only state mismatch")
        if pack.get("source_type") != "manual":
            raise ValueError(f"{cve}: expected reviewed manual source")
        check_manual_source(
            pack, (folder / "rules-exec.yar").read_text(encoding="utf-8"))
        packs.append(pack)
    pattern_count = sum(len(pack["rules"]) for pack in packs)
    if pattern_count != 25:
        raise ValueError("Research mask count has changed")
    if (CANDIDATES / "database-exec.yar").read_text(
            encoding="utf-8") != source_from_packs(packs):
        raise ValueError("Combined CVE source does not match checked packs")
    anchors = json.loads(
        (CANDIDATES / "machine-anchors.json").read_text(encoding="utf-8"))
    if set(anchors) != {"CVE-2026-33416", "CVE-2026-34757"}:
        raise ValueError("Expected bytecode anchor sets are missing")
    anchor_count = 0
    for cve, rows in anchors.items():
        reviewed_masks = {
            item["hex"] for pack in packs if pack["cve"] == cve
            for item in pack["rules"]
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
        raise ValueError("Incomplete original bytecode anchor set")
    matrix = json.loads(
        (CANDIDATES / "validation-matrix.json").read_text(encoding="utf-8"))
    if (matrix.get("native_yara_x_checked") is not False or
        {case["cve"] for case in matrix.get("cases", [])} != set(CVES) or any(
            case.get("status") != "CANDIDATE_ONLY"
            for case in matrix["cases"])):
        raise ValueError(
            "CVE evidence status cannot be promoted without native review")
    return {
        "status": "RESEARCH_SOURCE_CHECKED_NOT_PRODUCTION",
        "candidate_cves": len(packs),
        "patterns": pattern_count,
        "original_machine_anchors_checked": anchor_count,
        "native_yara_x": False
    }


def main() -> int:
    try:
        print(json.dumps(check(), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"RESEARCH CVE SOURCE REJECTED: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
