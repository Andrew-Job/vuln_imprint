"""Immutable Git source acquisition for trusted build recipes.

No CVE-specific logic. Source acquisition requires a pinned full commit hash;
branch/tag names are never accepted as identity. Worktrees must be built in
isolated CI workers: source recipes can execute arbitrary code.
"""
from __future__ import annotations
import hashlib
import json
import re
import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

COMMIT_RE = re.compile(r'(?:[a-f0-9]{40}|[a-f0-9]{64})\Z', re.I)


def get_git_source(entry: dict, work: Path) -> tuple[Path, dict]:
    url = entry.get('git')
    commit = entry.get('commit', '')
    if not isinstance(url, str) or not url:
        raise ValueError('git source requires git URL/path')
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError('git source must pin a full commit SHA (40 or 64 hex)')
    if any(ord(char) < 32 for char in url) or url.startswith('-'):
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
        # Git treats host:path / user@host:path as SSH even without ://.
        # Relative and home-expanded paths are ambiguous under git clone.
        raise ValueError('Git source path must be absolute and local')
    key = hashlib.sha256(
        (url + '\0' + commit.lower()).encode()).hexdigest()[:24]
    source = work / f'git-{key}'
    if not (source / '.git').is_dir():
        if source.exists():
            raise ValueError(
                'source destination exists but is not a Git checkout')
        clone_origin = url
        # Repository mirror is shared by all CVEs/build profiles in a batch.
        # The pinned checkout is still verified against the original remote SHA.
        mirror_cache = os.environ.get('VULNIMPRINT_GIT_MIRROR_CACHE')
        if mirror_cache:
            mirror = Path(mirror_cache).resolve() / (
                hashlib.sha256(url.encode()).hexdigest() + '.git')
            mirror.parent.mkdir(parents=True, exist_ok=True)
            if not mirror.is_dir():
                subprocess.run([
                    'git', 'clone', '--mirror', '--quiet', '--', url,
                    str(mirror)
                ],
                               check=True,
                               timeout=300)
            clone_origin = str(mirror)
        subprocess.run([
            'git', 'clone', '--quiet', '--no-checkout', '--', clone_origin,
            str(source)
        ],
                       check=True,
                       timeout=180)
    subprocess.run(
        ['git', '-C',
         str(source), 'checkout', '--quiet', '--detach', commit],
        check=True,
        timeout=60)
    actual = subprocess.run(
        ['git', '-C', str(source), 'rev-parse', 'HEAD'],
        check=True,
        capture_output=True,
        text=True).stdout.strip()
    if actual.lower() != commit.lower():
        raise ValueError(f'Git HEAD mismatch: wanted {commit}, got {actual}')
    status = subprocess.run([
        'git', '-C',
        str(source), 'status', '--porcelain', '--untracked-files=all'
    ],
                            check=True,
                            capture_output=True,
                            text=True).stdout
    if status.strip():
        raise ValueError('Git checkout contains modified or untracked files')
    info = {
        'type': 'git',
        'url': url,
        'commit': actual,
        'checkout': str(source.resolve())
    }
    return source, info
