#!/usr/bin/env python3
"""Smoke-test the Scanner with five selected production CVEs.

Generates ELF byte fixtures from the canonical production rules. This tests
native matching and file offsets, not CVE detection accuracy.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from factory.patterns import Pattern

ROOT = Path(__file__).resolve().parents[1]
SMOKE_CVES = (
    "CVE-2026-22695",
    "CVE-2026-22801",
    "CVE-2026-25646",
    "CVE-2026-33416",
    "CVE-2026-34757",
)


def run(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {args!r}\n"
            f"stdout={result.stdout[-2000:]}\nstderr={result.stderr[-2000:]}")
    return result.stdout


def fixture_patterns(root: Path = ROOT) -> list[tuple[str, str, str, bytes]]:
    result = []
    for cve in SMOKE_CVES:
        pack = json.loads((root / "signatures" / cve /
                           "pack.json").read_text(encoding="utf-8"))
        production = [
            record for record in pack["records"]
            if record["channel"] == "production"
        ]
        if not production:
            raise ValueError(f"{cve}: missing production smoke-test record")
        for record in production:
            for index, rule in enumerate(record["rules"]):
                pattern = Pattern.from_hex(rule["hex"])
                body = bytes(byte if mask else 0
                             for byte, mask in zip(pattern.data, pattern.mask))
                result.append((cve, record["record_id"], f"v{index}", body))
    if not result:
        raise ValueError("no smoke-test production patterns")
    return result


def build_fixture(directory: Path, patterns: list,
                  cc: str) -> tuple[Path, Path]:
    asm = [
        '.section .text.vulnimprint,"ax",@progbits',
        '.globl vi_probes',
        '.type vi_probes, @function',
        'vi_probes:',
    ]
    for _cve, _record_id, _pattern, data in patterns:
        asm.extend([
            '.balign 16',
            '.byte ' + ', '.join(f'0x{byte:02x}' for byte in data),
            '.fill 64, 1, 0x90',
        ])
    asm.extend([
        '.size vi_probes, .-vi_probes',
        '.section .note.GNU-stack,"",@progbits',
    ])
    source = directory / "probes.S"
    source.write_text("\n".join(asm) + "\n", encoding="utf-8")
    main = directory / "main.c"
    main.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    positive = directory / "machine-patterns"
    negative = directory / "no-patterns"
    run(cc, "-O2", str(main), str(source), "-o", str(positive))
    run(cc, "-O2", str(main), "-o", str(negative))
    return positive, negative


def check(scanner: Path, database: Path, cc: str = "cc") -> dict:
    patterns = fixture_patterns()
    with tempfile.TemporaryDirectory(prefix="vi-cve-native-") as temp:
        positive, negative = build_fixture(Path(temp), patterns, cc)
        image = positive.read_bytes()
        expected = set()
        for cve, record_id, pattern_name, body in patterns:
            offset = image.find(body)
            if offset < 0:
                raise ValueError(
                    f"fixture bytes missing: {record_id}/{pattern_name}")
            expected.add((cve, record_id, pattern_name, offset, len(body)))

        report = json.loads(
            run(str(scanner), "scan", "--compiled", str(database), "--json",
                str(positive)))
        if (report.get("schema") != "vulnimprint.scan.yarax.v2" or
                report.get("engine") != "yara-x" or report.get("errors") != 0 or
                report.get("truncated_files") != 0 or
                len(report.get("results", [])) != 1 or
                report["results"][0]["error"] is not None):
            raise ValueError(f"invalid native positive result: {report}")
        matches = report["results"][0]["matches"]
        actual = {(item["cve"], item["record_id"], item["pattern"].lstrip("$"),
                   int(item["file_offset"], 16), item["length"])
                  for item in matches
                  if item["executable"]}
        missing = expected - actual
        if missing:
            raise ValueError(
                f"native engine missed production patterns: {sorted(missing)}")
        actual_cves = {cve for cve, *_rest in expected}
        if (report["cve_count"] != len(actual_cves) or
                set(report["unique_cves"]) != actual_cves):
            raise ValueError(
                "native CVE aggregation does not match production patterns")
        if len(matches) < len(expected):
            raise ValueError("native scan returned fewer matches than expected")

        clean = json.loads(
            run(str(scanner), "scan", "--compiled", str(database), "--json",
                str(negative)))
        if (clean["errors"] != 0 or clean["cve_count"] != 0 or
                clean["results"][0]["matches"]):
            raise ValueError(
                "negative executable unexpectedly matched production rules")

        return {
            "status": "PASS",
            "engine": "native-yara-x-capi",
            "cves": len(actual_cves),
            "records": len({record_id for _, record_id, *_ in expected}),
            "pattern_fixtures": len(patterns),
            "positive_file_offsets_checked": len(expected),
            "negative_matches": 0,
            "cve_accuracy": "NOT_ESTABLISHED",
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--database",
                        type=Path,
                        required=True,
                        help="compiled production database.yarc")
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    try:
        print(
            json.dumps(check(args.scanner.resolve(), args.database.resolve(),
                             args.cc),
                       sort_keys=True))
    except (OSError, RuntimeError, ValueError, KeyError, AssertionError,
            subprocess.TimeoutExpired) as exc:
        print(f"NATIVE CVE FUNCTIONAL CHECK FAILED: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
