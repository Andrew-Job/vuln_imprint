"""Promote a fully validated CVE case into a contributor branch.

This tool never changes classification or invents evidence. It runs the real
C++ YARA-X scanner over the complete independent case corpus before copying
source files into the canonical Git layout. Merge-time native CI rechecks the
full corpus against the complete database.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from scripts.check_validated_signatures import check
from tools.production_db import CVE, ReleaseRejected, sha256, validate_case

REQUIRED = ("pack.json", "rules-exec.yar", "reviewed-evidence.json")


def prepare(case: Path, scanner: Path, repo: Path) -> dict:
    """Validate one case and prepare canonical PR files; reject on any error."""
    case = Path(case)
    scanner = Path(scanner)
    repo = Path(repo).resolve()
    if case.is_symlink() or not case.is_dir():
        raise ReleaseRejected("case directory must be a real directory")
    if not scanner.is_file() or not scanner.stat().st_mode & 0o111:
        raise ReleaseRejected("an executable native YARA-X scanner is required")
    for name in REQUIRED:
        source = case / name
        if source.is_symlink() or not source.is_file():
            raise ReleaseRejected(f"missing or symlinked case input: {name}")
    pack = json.loads((case / "pack.json").read_text(encoding="utf-8"))
    cve = pack.get("cve")
    if not isinstance(cve, str) or not CVE.fullmatch(cve) or case.name != cve:
        raise ReleaseRejected("case name and pack CVE must match")

    # This executes real affected/fixed/backport/unrelated scans and verifies
    # all eight versioned compiler lanes. No metadata-only approval is possible.
    evidence = validate_case(case, scanner)
    if evidence["quality"] != "CVE_SPECIFIC_VALIDATED":
        raise ReleaseRejected("case does not satisfy production admission")

    signatures = repo / "signatures" / "validated"
    if not signatures.is_dir() or signatures.is_symlink():
        raise ReleaseRejected("canonical validated tree is missing")
    target = signatures / cve
    if target.exists() or target.is_symlink():
        raise ReleaseRejected(f"{cve} already exists; edit it in a branch and rerun PR CI")

    original_digests = {name: sha256(case / name) for name in REQUIRED}
    target.mkdir()
    try:
        for name in REQUIRED:
            if sha256(case / name) != original_digests[name]:
                raise ReleaseRejected(f"case input changed during validation: {name}")
            shutil.copyfile(case / name, target / name)
            if sha256(target / name) != original_digests[name]:
                raise ReleaseRejected(f"copied source digest mismatch: {name}")
        admitted = check(repo)
        if cve not in admitted:
            raise ReleaseRejected(f"prepared CVE not admitted by canonical source gate: {cve}")
    except BaseException:
        shutil.rmtree(target)
        raise
    return {"status": "READY_FOR_REVIEW", "cve": cve,
            "source_files": {name: original_digests[name] for name in REQUIRED},
            "independent_samples": len(evidence["samples"]),
            "canonical_directory": str(target)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=Path, required=True,
                        help="reviewed CVE case with actual holdout specimens")
    parser.add_argument("--scanner", type=Path, required=True,
                        help="real C++ VulnImprint/YARA-X executable")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        print(json.dumps(prepare(args.case, args.scanner, args.repo), indent=2, sort_keys=True))
    except (ReleaseRejected, OSError, ValueError, TypeError, KeyError) as exc:
        parser.exit(2, f"CVE PREPARATION REJECTED: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
