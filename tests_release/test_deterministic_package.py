"""The product archive must not depend on filesystem timestamps or gzip clock."""
from __future__ import annotations

import hashlib
import os
import tarfile
from pathlib import Path

import pytest

from tools.package_product import write_reproducible_archive
from tools.production_db import ReleaseRejected


def test_reproducible_archive_content_and_metadata(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1735689600")
    root = tmp_path / "root"
    (root / "bin").mkdir(parents=True)
    binary = root / "bin" / "vulnimprint-scan"
    binary.write_bytes(b"same binary")
    binary.chmod(0o755)
    a = tmp_path / "a.tar.gz"
    b = tmp_path / "b.tar.gz"
    write_reproducible_archive(root, a)
    os.utime(binary, (1, 1))
    os.utime(root / "bin", (2, 2))
    write_reproducible_archive(root, b)
    assert hashlib.sha256(a.read_bytes()).digest() == hashlib.sha256(b.read_bytes()).digest()
    with tarfile.open(a, "r:gz") as archive:
        names = archive.getnames()
        assert names == ["vulnimprint", "vulnimprint/bin", "vulnimprint/bin/vulnimprint-scan"]
        assert all(m.uid == 0 and m.gid == 0 and m.mtime == 1735689600 for m in archive)
        assert archive.getmember("vulnimprint/bin/vulnimprint-scan").mode == 0o755


def test_invalid_source_date_epoch_rejected(tmp_path: Path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "NaN")
    with pytest.raises(ReleaseRejected, match="SOURCE_DATE_EPOCH"):
        write_reproducible_archive(root, tmp_path / "bad.tar.gz")
