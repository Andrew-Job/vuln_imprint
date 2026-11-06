#!/usr/bin/env python3
"""Strict bounded extraction of independently reviewed evidence archives.

Only safe paths/types are accepted, contents are written into a private new
staging directory, and the requested destination appears only after a complete
verified extraction. No tar paths or links are allowed to escape the stage.
"""
from __future__ import annotations
import argparse
import hashlib
import os
import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

LIMIT_ARCHIVE = 2 * 1024**3
LIMIT_EXPANDED = 8 * 1024**3
LIMIT_FILE = 512 * 1024**2
LIMIT_MEMBERS = 100000


def unpack(archive: Path, expected: str, dest: Path):
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('invalid corpus SHA-256')
    if not archive.is_file() or archive.stat().st_size > LIMIT_ARCHIVE:
        raise ValueError('reviewed corpus archive missing or oversized')
    if dest.exists() or dest.is_symlink():
        raise ValueError('refusing to overwrite existing specimen destination')
    h = hashlib.sha256()
    with archive.open('rb') as inp:
        while chunk := inp.read(1 << 20):
            h.update(chunk)
    if h.hexdigest() != expected:
        raise ValueError('reviewed corpus SHA256 mismatch')
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.corpus-', dir=dest.parent))
    try:
        with tarfile.open(archive, 'r:gz') as t:
            members = t.getmembers()
            if len(members) > LIMIT_MEMBERS:
                raise ValueError('too many specimen entries')
            if sum(m.size for m in members) > LIMIT_EXPANDED:
                raise ValueError('aggregate expanded corpus exceeds size limit')
            seen = set()
            for member in members:
                original = member.name
                item = PurePosixPath(original)
                if (not original or original.startswith('/') or
                        '\\' in original or
                        any(part in ('', '.', '..')
                            for part in original.split('/')) or
                        item.is_absolute() or original in seen):
                    raise ValueError('unsafe or duplicate specimen path')
                seen.add(original)
                if not (member.isfile() or member.isdir()):
                    raise ValueError(
                        'corpus links and special files are forbidden')
                if member.size > LIMIT_FILE:
                    raise ValueError('oversized specimen')
            for member in members:
                path = staging / member.name
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                    continue
                path.parent.mkdir(parents=True, exist_ok=True)
                with t.extractfile(member) as src, path.open('xb') as out:
                    while data := src.read(1 << 20):
                        out.write(data)
        os.replace(staging, dest)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        unpack(a.archive, a.sha256, a.output)
        return 0
    except (ValueError, OSError, tarfile.TarError) as e:
        print(e, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
