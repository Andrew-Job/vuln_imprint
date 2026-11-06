"""Acquire commit-pinned Git sources using an optional immutable-object mirror.

Mirrors are keyed by the full source locator and never used as authority for
an unpinned revision. An existing checkout is never silently overwritten.
Build recipes still require an isolated worker: acquiring source is not a
sandbox for running its code.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import re
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

COMMIT_RE = re.compile(r'(?:[a-f0-9]{40}|[a-f0-9]{64})\Z', re.I)


def _git(*args: str, timeout: int = 60) -> str:
    return subprocess.run(['git', *map(str, args)],
                          check=True,
                          capture_output=True,
                          text=True,
                          timeout=timeout).stdout.strip()


@contextmanager
def _locked(path: Path):
    """Serialize cache construction across local processes, including failures."""
    with path.open('a+b') as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _source_locator(url: object) -> str:
    if not isinstance(url, str) or not url or any(ord(c) < 32 for c in url):
        raise ValueError('unsafe Git source locator')
    if url.startswith('-'):
        raise ValueError('unsafe Git source locator')
    if '://' in url:
        parsed = urlsplit(url)
        if parsed.scheme == 'https':
            if (not parsed.hostname or parsed.username or parsed.password or
                    not parsed.path.startswith('/') or parsed.query or
                    parsed.fragment):
                raise ValueError(
                    'HTTPS Git source requires a canonical host/path')
        elif parsed.scheme == 'file':
            if (parsed.netloc not in ('', 'localhost') or
                    not parsed.path.startswith('/') or parsed.query or
                    parsed.fragment):
                raise ValueError(
                    'file Git source must be a local absolute path')
        else:
            raise ValueError('Git source transport must be HTTPS or local file')
    elif (':' in url or '@' in url or url.startswith('~') or
          not Path(url).is_absolute()):
        raise ValueError('Git source path must be absolute and local')
    return url


def _mirror_for(url: str, commit: str, cache: Path) -> Path:
    """Initialize or refresh a mirror only when the requested object is absent."""
    cache.mkdir(parents=True, exist_ok=True)
    identity = hashlib.sha256(url.encode()).hexdigest()
    mirror = cache / (identity + '.git')
    with _locked(cache / (identity + '.lock')):
        if mirror.is_symlink():
            raise ValueError('Git mirror may not be a symlink')
        if not mirror.exists():
            with tempfile.TemporaryDirectory(dir=cache,
                                             prefix='.mirror-') as tmp:
                staging = Path(tmp) / 'repo.git'
                _git('clone',
                     '--mirror',
                     '--quiet',
                     '--',
                     url,
                     staging,
                     timeout=300)
                os.replace(staging, mirror)
        if not mirror.is_dir() or _git('-C', mirror, 'rev-parse',
                                       '--is-bare-repository') != 'true':
            raise ValueError('cached Git mirror is not a bare repository')
        if _git('-C', mirror, 'config', '--get', 'remote.origin.url') != url:
            raise ValueError('cached Git mirror origin mismatch')
        if subprocess.run([
                'git', '-C',
                str(mirror), 'cat-file', '-e', f'{commit}^{{commit}}'
        ],
                          capture_output=True,
                          check=False,
                          timeout=30).returncode:
            # Do not prune: retained objects may belong to another pinned
            # commit referenced by an earlier Factory build.
            _git('-C', mirror, 'remote', 'update', timeout=300)
            _git('-C',
                 mirror,
                 'cat-file',
                 '-e',
                 f'{commit}^{{commit}}',
                 timeout=30)
    return mirror


def get_git_source(entry: dict,
                   work: Path,
                   mirror_cache: Path | None = None) -> tuple[Path, dict]:
    url = _source_locator(entry.get('git'))
    commit = entry.get('commit', '')
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise ValueError('git source must pin a full commit SHA (40 or 64 hex)')
    commit = commit.lower()
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256((url + '\0' + commit).encode()).hexdigest()[:24]
    source = work / f'git-{key}'
    configured_cache = mirror_cache if mirror_cache is not None else os.environ.get(
        'VULNIMPRINT_GIT_MIRROR_CACHE')
    with _locked(work / f'.git-{key}.lock'):
        if source.is_symlink():
            raise ValueError('Git checkout may not be a symlink')
        if source.exists():
            if not (source / '.git').is_dir():
                raise ValueError(
                    'source destination exists but is not a Git checkout')
            if Path(_git('-C', source, 'rev-parse',
                         '--show-toplevel')).resolve() != source.resolve():
                raise ValueError('Git checkout does not match its destination')
            if _git('-C', source, 'status', '--porcelain',
                    '--untracked-files=all'):
                raise ValueError(
                    'Git checkout contains modified or untracked files')
            if _git('-C', source, 'rev-parse', 'HEAD').lower() != commit:
                raise ValueError(
                    'cached checkout HEAD does not match pinned commit')
        else:
            origin = url
            if configured_cache:
                origin = str(
                    _mirror_for(url, commit,
                                Path(configured_cache).resolve()))
            with tempfile.TemporaryDirectory(dir=work,
                                             prefix='.checkout-') as tmp:
                staging = Path(tmp) / 'repo'
                _git('clone',
                     '--quiet',
                     '--no-checkout',
                     '--',
                     origin,
                     staging,
                     timeout=180)
                _git('-C', staging, 'checkout', '--quiet', '--detach', commit)
                os.replace(staging, source)
        actual = _git('-C', source, 'rev-parse', 'HEAD')
        if actual.lower() != commit:
            raise ValueError(
                f'Git HEAD mismatch: wanted {commit}, got {actual}')
        if _git('-C', source, 'status', '--porcelain', '--untracked-files=all'):
            raise ValueError(
                'Git checkout contains modified or untracked files')
    return source, {
        'type': 'git',
        'url': url,
        'commit': actual,
        'checkout': str(source.resolve())
    }
