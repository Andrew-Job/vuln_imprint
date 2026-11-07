#!/usr/bin/env python3
"""Validate all changed CVE-owned records in a pull request."""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from scripts.check_cve_source_tree import check
from tools.production_db import ReleaseRejected

CVE_PATH = re.compile(r"signatures/(CVE-\d{4}-\d{4,})(?:/|$)")


def gate(root: Path, base: str) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{40}", base):
        raise ReleaseRejected("PR base must be an exact Git commit")
    command = [
        "git", "-C",
        str(root), "diff", "--name-only", "--no-renames",
        "--diff-filter=ACDMRT", f"{base}..HEAD", "--", "signatures/"
    ]
    result = subprocess.run(command,
                            check=True,
                            capture_output=True,
                            text=True,
                            timeout=30)
    changed = sorted({
        match.group(1)
        for line in result.stdout.splitlines()
        if (match := CVE_PATH.match(line))
    })
    # The source checker validates all changed and unchanged records. There is
    # no separate candidate/reviewed admission state: channel is test/production.
    check(root)
    for cve in changed:
        directory = root / "signatures" / cve
        if not directory.is_dir():
            raise ReleaseRejected(
                f"{cve}: preserve the CVE source record; use research.json "
                "when no machine record remains")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--root",
                        type=Path,
                        default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        changed = gate(args.root, args.base)
    except (ReleaseRejected, OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        print(f"CVE CHANGE REJECTED: {exc}", file=sys.stderr)
        return 2
    print(f"CVE source changes validated: {', '.join(changed) or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
