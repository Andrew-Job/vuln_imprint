"""Validate source ZIP rules against real Python zipfile output."""
from __future__ import annotations

import zipfile
import warnings

import pytest

from factory.archive_safety import extract_zip


def _archive(tmp_path, entries):
    target = tmp_path / 'source.zip'
    with zipfile.ZipFile(target, 'w') as archive:
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore',
                                    message='Duplicate name:',
                                    category=UserWarning)
            for name, body in entries:
                archive.writestr(name, body)
    return target


def test_normal_zip_extracts_single_file(tmp_path):
    archive = _archive(tmp_path, [('prefix/file.c', 'int x;')])
    extract_zip(archive, tmp_path / 'out')
    assert (tmp_path / 'out/prefix/file.c').read_text() == 'int x;'


@pytest.mark.parametrize('entries', [
    [('a/../escape', 'x')],
    [('a/./file', 'x')],
    [('a/file', 'x'), ('a/file', 'y')],
    [('a/file', 'x'), ('a//file', 'y')],
    [('a\\file', 'x')],
    [('/abs/file', 'x')],
])
def test_zip_rejects_normalized_or_unsafe_names(tmp_path, entries):
    archive = _archive(tmp_path, entries)
    with pytest.raises(ValueError, match='unsafe|ambiguous|duplicate'):
        extract_zip(archive, tmp_path / 'out')
    assert not (tmp_path / 'out').exists()


def test_zip_rejects_more_than_allowed_members(tmp_path, monkeypatch):
    from factory import archive_safety
    monkeypatch.setattr(archive_safety, 'MAX_MEMBERS', 1)
    archive = _archive(tmp_path, [('a', '1'), ('b', '2')])
    with pytest.raises(ValueError, match='too many members'):
        extract_zip(archive, tmp_path / 'out')
