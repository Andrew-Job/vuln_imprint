"""Bounded, fail-closed extraction of ZIP source snapshots."""
from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath

MAX_MEMBERS = 100000
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024


def extract_zip(archive: Path, output: Path) -> None:
    """Preflight all paths and types before extracting any ZIP member."""
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ValueError('source ZIP has too many members')
        total = 0
        seen = set()
        for info in infos:
            name = info.filename
            path = PurePosixPath(name)
            mode = (info.external_attr >> 16) & 0o170000
            normalized = path.as_posix().rstrip('/')
            if (not normalized or name.startswith('/') or
                '\\' in name or ':' in name or
                any(part in ('.', '..', '') for part in name.rstrip('/').split('/')) or
                normalized in seen or mode not in (0, 0o040000, 0o100000) or
                (name.endswith('/') != info.is_dir())):
                raise ValueError('unsafe, duplicate or ambiguous ZIP member')
            seen.add(normalized)
            total += info.file_size
            if total > MAX_EXPANDED_BYTES or info.file_size > MAX_FILE_BYTES:
                raise ValueError('source ZIP expanded size exceeds limits')
        for info in infos:
            extracted = Path(zf.extract(info, output))
            if not info.is_dir() and extracted.stat().st_size != info.file_size:
                raise ValueError('ZIP extracted size differs from declared size')
