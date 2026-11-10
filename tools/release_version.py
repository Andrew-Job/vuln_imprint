#!/usr/bin/env python3
"""Calculate MAJOR.MINOR.PATTERNS from published releases and production DB."""
import argparse
import json
import os
import re
import subprocess
from pathlib import Path

# Updated through a pull request.
MAJOR = 0
_TAG = re.compile(r"v(\d+)\.(\d+)\.\d+\Z")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    args = parser.parse_args()

    index = json.loads(
        (args.database / "index.json").read_text(encoding="utf-8"))
    pages = json.loads(
        subprocess.check_output([
            "gh", "api", "--paginate", "--slurp",
            f"repos/{os.environ['GITHUB_REPOSITORY']}/releases?per_page=100"
        ],
                                text=True))

    minors = []
    for page in pages:
        for release in page:
            if release.get("draft") or not release.get("published_at"):
                continue
            match = _TAG.fullmatch(release.get("tag_name", ""))
            if match and int(match[1]) == MAJOR:
                minors.append(int(match[2]))

    print(f"v{MAJOR}.{max(minors, default=0) + 1}.{index['pattern_count']}")


if __name__ == "__main__":
    main()
