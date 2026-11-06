"""Git source mirror regression for pinned commits across upstream updates."""

import subprocess
from pathlib import Path

from factory.git_source import get_git_source


def _git(*args):
    return subprocess.run(['git', *map(str, args)],
                          capture_output=True,
                          text=True,
                          check=True,
                          timeout=30).stdout.strip()


def test_cached_mirror_can_fetch_a_later_upstream_commit(tmp_path):
    origin = tmp_path / 'origin'
    _git('init', '-q', origin)
    _git('-C', origin, 'config', 'user.email', 'test@example.invalid')
    _git('-C', origin, 'config', 'user.name', 'Test')
    first_file = origin / 'data.txt'
    first_file.write_text('first\n')
    _git('-C', origin, 'add', 'data.txt')
    _git('-C', origin, 'commit', '-q', '-m', 'first')
    first = _git('-C', origin, 'rev-parse', 'HEAD')

    cache = tmp_path / 'mirrors'
    work = tmp_path / 'checkouts'
    work.mkdir()
    source, info = get_git_source({
        'git': str(origin),
        'commit': first
    },
                                  work,
                                  mirror_cache=cache)
    assert info['commit'] == first
    assert (source / 'data.txt').read_text() == 'first\n'

    first_file.write_text('second\n')
    _git('-C', origin, 'add', 'data.txt')
    _git('-C', origin, 'commit', '-q', '-m', 'second')
    second = _git('-C', origin, 'rev-parse', 'HEAD')
    assert second != first
    latest, info = get_git_source({
        'git': str(origin),
        'commit': second
    },
                                  work,
                                  mirror_cache=cache)
    assert info['commit'] == second
    assert (latest / 'data.txt').read_text() == 'second\n'
    previous, _ = get_git_source({
        'git': str(origin),
        'commit': first
    },
                                 work,
                                 mirror_cache=cache)
    assert (previous / 'data.txt').read_text() == 'first\n'


def test_checkout_with_local_edits_is_never_reset(tmp_path):
    origin = tmp_path / 'origin'
    _git('init', '-q', origin)
    _git('-C', origin, 'config', 'user.email', 'test@example.invalid')
    _git('-C', origin, 'config', 'user.name', 'Test')
    (origin / 'data.txt').write_text('original\n')
    _git('-C', origin, 'add', 'data.txt')
    _git('-C', origin, 'commit', '-q', '-m', 'initial')
    commit = _git('-C', origin, 'rev-parse', 'HEAD')
    checkout, _ = get_git_source({
        'git': str(origin),
        'commit': commit
    }, tmp_path / 'work')
    (checkout / 'data.txt').write_text('local changes\n')
    import pytest
    with pytest.raises(ValueError, match='modified'):
        get_git_source({
            'git': str(origin),
            'commit': commit
        }, tmp_path / 'work')
    assert (checkout / 'data.txt').read_text() == 'local changes\n'


def test_corrupted_or_replaced_mirror_is_rejected(tmp_path):
    import hashlib
    import pytest
    origin = tmp_path / 'origin'
    _git('init', '-q', origin)
    (origin / 'data.txt').write_text('data\n')
    _git('-C', origin, 'add', 'data.txt')
    _git('-C', origin, '-c', 'user.email=test@example.invalid', '-c',
         'user.name=Test', 'commit', '-q', '-m', 'initial')
    commit = _git('-C', origin, 'rev-parse', 'HEAD')
    cache = tmp_path / 'cache'
    cache.mkdir()
    key = hashlib.sha256(str(origin).encode()).hexdigest() + '.git'
    target = cache / key
    target.symlink_to(origin, target_is_directory=True)
    with pytest.raises(ValueError, match='symlink'):
        get_git_source({
            'git': str(origin),
            'commit': commit
        },
                       tmp_path / 'work',
                       mirror_cache=cache)
    target.unlink()
    _git('clone', '--mirror', '-q', origin, target)
    _git('-C', target, 'remote', 'set-url', 'origin', str(tmp_path / 'other'))
    with pytest.raises(ValueError, match='origin mismatch'):
        get_git_source({
            'git': str(origin),
            'commit': commit
        },
                       tmp_path / 'work',
                       mirror_cache=cache)


def test_concurrent_users_of_same_mirror(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    origin = tmp_path / 'origin'
    _git('init', '-q', origin)
    (origin / 'data.txt').write_text('shared\n')
    _git('-C', origin, 'add', 'data.txt')
    _git('-C', origin, '-c', 'user.email=test@example.invalid', '-c',
         'user.name=Test', 'commit', '-q', '-m', 'initial')
    commit = _git('-C', origin, 'rev-parse', 'HEAD')

    def fetch(index):
        checkout, _ = get_git_source({
            'git': str(origin),
            'commit': commit
        },
                                     tmp_path / f'work-{index}',
                                     mirror_cache=tmp_path / 'cache')
        return (checkout / 'data.txt').read_text()

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(fetch, range(4))) == ['shared\n'] * 4
