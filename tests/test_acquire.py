import json, tarfile, zipfile, hashlib, subprocess, shutil
from pathlib import Path
import pytest
from factory.pipeline import acquire, run


def test_sha_pinning_and_zip_member(tmp_path):
    archive = tmp_path / 'sample.whl'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('wheel/a.so', b'ELF-placeholder')
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    actual = acquire(
        {
            'path': str(archive),
            'sha256': sha,
            'member_glob': 'wheel/*.so'
        }, tmp_path, tmp_path)
    assert actual.read_bytes() == b'ELF-placeholder'
    with pytest.raises(ValueError, match='SHA256'):
        acquire({'path': str(archive), 'sha256': '0' * 64}, tmp_path, tmp_path)


def test_archive_member_and_build_recipe(tmp_path):
    # Shows that any CVE manifest can reference build artifacts without
    # embedding Python logic for that CVE in the generator.
    src = tmp_path / 'src'
    src.mkdir()
    code = '__attribute__((noinline)) int characteristic(int n){return n < 131 ? n*43+7 : n-31;}'
    (src / 'bad.c').write_text(code)
    (src / 'good.c').write_text(code.replace('131', '67'))
    archive = tmp_path / 'sources.tar.gz'
    with tarfile.open(archive, 'w:gz') as tf:
        for name in ('bad.c', 'good.c'):
            tf.add(src / name, arcname=name)
    commands = []
    for label in ('bad', 'good'):
        commands.append([
            'gcc', '-O0', '-c', '{source_dir}/' + label + '.c', '-o',
            '{workspace}/' + label + '.o'
        ])
    data = {
        'schema_version':
            1,
        'cve':
            'CVE-2099-91011',
        'builds': [{
            'name': 'gcc-o0',
            'source': {
                'path': str(archive),
                'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()
            },
            'commands': commands
        }],
        'hints': {
            'symbols': ['characteristic']
        },
        'mining': {
            'min_instructions': 3,
            'min_bytes': 16,
            'min_fixed': 14
        },
        'samples': [{
            'id': 'bad',
            'label': 'affected',
            'split': 'train',
            'path': '{work}/build-gcc-o0/bad.o'
        }, {
            'id': 'fixed',
            'label': 'fixed',
            'split': 'train',
            'path': '{work}/build-gcc-o0/good.o'
        }]
    }
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(data))
    result = run(path, tmp_path / 'result')
    assert result['mining']['distinct'] > 0
    assert result['metrics']['train'] == {'TP': 1, 'TN': 1}
    a = tmp_path / 'archive.a'
    subprocess.run(
        ['ar', 'rcs',
         str(a),
         str(tmp_path / 'result/work/build-gcc-o0/bad.o')],
        check=True)
    out = acquire({'path': str(a), 'member_glob': 'bad.o'}, tmp_path, tmp_path)
    assert out.read_bytes().startswith(b'\x7fELF')


def test_url_acquisition_rejects_partial_download_and_corrupt_cache(
        tmp_path, monkeypatch):
    """Only validated bytes may enter a reusable fetch cache."""
    import io
    from factory import pipeline

    url = 'https://sources.example.org/test.tar.gz'
    expected = hashlib.sha256(b'expected bytes').hexdigest()

    class Response(io.BytesIO):

        def geturl(self):
            return url

    class Opener:

        def __init__(self, payload):
            self.payload = payload

        def open(self, *args, **kwargs):
            return Response(self.payload)

    monkeypatch.setattr(pipeline.urllib.request, 'build_opener',
                        lambda *args: Opener(b'corrupt bytes'))
    with pytest.raises(ValueError, match='SHA256 mismatch'):
        acquire({'url': url, 'sha256': expected}, tmp_path, tmp_path)
    assert not list(tmp_path.glob('download-*'))
    assert not list(tmp_path.glob('.download-*'))

    monkeypatch.setattr(pipeline.urllib.request, 'build_opener',
                        lambda *args: Opener(b'expected bytes'))
    artifact = acquire({'url': url, 'sha256': expected}, tmp_path, tmp_path)
    assert artifact.read_bytes() == b'expected bytes'
    artifact.write_bytes(b'incomplete cache file')
    refetched = acquire({'url': url, 'sha256': expected}, tmp_path, tmp_path)
    assert refetched.read_bytes() == b'expected bytes'


def test_bad_build_manifest_rejected_before_external_commands(
        tmp_path, monkeypatch):
    from factory.pipeline import _prepare
    import factory.pipeline as pipeline

    monkeypatch.setattr(
        pipeline.subprocess, 'run',
        lambda *args, **kwargs: pytest.fail('unvalidated command executed'))
    bad = {
        'builds': [
            {
                'name': 'first',
                'source': {
                    'path': '/unused'
                },
                'commands': [['echo', 'danger']]
            },
            {
                'name': 'second',
                'source': {
                    'path': '/unused'
                },
                'commands': 'not argv'
            },
        ]
    }
    with pytest.raises(ValueError, match='commands must be'):
        _prepare(bad, tmp_path, tmp_path / 'work')
    assert not (tmp_path / 'work' / 'build-first').exists()
    with pytest.raises(ValueError, match='builds must be a list'):
        _prepare({'builds': 'bad'}, tmp_path, tmp_path / 'work')


def test_batch_freeze_rejects_malformed_build_entries(tmp_path, monkeypatch):
    from factory import batch

    def unexpected_network(*args, **kwargs):
        pytest.fail('malformed manifest must not contact external Git')

    monkeypatch.setattr(batch, 'resolve_git_ref', unexpected_network)
    malformed = [
        [],
        {
            'builds': 'invalid'
        },
        {
            'builds': ['not-a-build']
        },
        {
            'builds': [{
                'source': []
            }]
        },
        {
            'builds': [{
                'source': {
                    'git': 42,
                    'ref': 'v1.0'
                }
            }]
        },
    ]
    catalog = tmp_path / 'CVE-2099-12345.json'
    for document in malformed:
        catalog.write_text(json.dumps(document))
        with pytest.raises(ValueError):
            batch.freeze_manifest(catalog, tmp_path / 'locked.json')
        assert not (tmp_path / 'locked.json').exists()


def test_zip_distinct_members_with_same_basename_never_share_cached_bytes(
        tmp_path):
    archive = tmp_path / 'both.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('affected/module.o', b'VULNERABLE BYTES')
        zf.writestr('fixed/module.o', b'PATCHED BYTES')

    affected = acquire({
        'path': str(archive),
        'member': 'affected/module.o'
    }, tmp_path, tmp_path)
    fixed = acquire({
        'path': str(archive),
        'member': 'fixed/module.o'
    }, tmp_path, tmp_path)
    assert affected != fixed
    assert affected.read_bytes() == b'VULNERABLE BYTES'
    assert fixed.read_bytes() == b'PATCHED BYTES'

    # Reusing a corrupt on-disk cache must not contaminate the next study.
    fixed.write_bytes(b'STALE CACHED SAMPLE')
    assert acquire({
        'path': str(archive),
        'member': 'fixed/module.o'
    }, tmp_path, tmp_path).read_bytes() == b'PATCHED BYTES'


def test_rebuild_replaces_sources_and_old_build_artifacts(tmp_path):
    from factory.pipeline import _prepare
    import io
    import sys

    archive = tmp_path / 'upstream.tar.gz'
    workspace = tmp_path / 'work'
    workspace.mkdir()

    def write_archive(payload):
        with tarfile.open(archive, 'w:gz') as tf:
            info = tarfile.TarInfo('src/state.txt')
            data = payload.encode()
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        return hashlib.sha256(archive.read_bytes()).hexdigest()

    def manifest(digest):
        return {
            'builds': [{
                'name':
                    'one',
                'source': {
                    'path': str(archive),
                    'sha256': digest
                },
                'commands': [[
                    sys.executable,
                    '-c',
                    'import pathlib,sys; '
                    'p=pathlib.Path(sys.argv[1]); '
                    'pathlib.Path(sys.argv[2]).write_bytes(p.read_bytes())',
                    '{source_dir}/src/state.txt',
                    '{workspace}/built.o',
                ]],
            }]
        }

    first_sha = write_archive('VULNERABLE SOURCE')
    _prepare(manifest(first_sha), tmp_path, workspace)
    folder = workspace / 'build-one'
    assert (folder / 'built.o').read_bytes() == b'VULNERABLE SOURCE'
    (folder / 'stale.o').write_bytes(b'OLD OBJECT')

    second_sha = write_archive('PATCHED SOURCE')
    assert second_sha != first_sha
    _prepare(manifest(second_sha), tmp_path, workspace)
    assert (folder / 'source/src/state.txt').read_bytes() == b'PATCHED SOURCE'
    assert (folder / 'built.o').read_bytes() == b'PATCHED SOURCE'
    assert not (folder / 'stale.o').exists()
    assert json.loads(
        (folder / 'source-provenance.json').read_text())['sha256'] == second_sha


def test_failed_source_extraction_leaves_no_reusable_directory(tmp_path):
    from factory.pipeline import _prepare
    import io

    archive = tmp_path / 'upstream.tar'
    work = tmp_path / 'work'
    work.mkdir()
    source = {'path': str(archive)}
    manifest = {'builds': [{'name': 'one', 'source': source, 'commands': []}]}
    with tarfile.open(archive, 'w') as tf:
        invalid = tarfile.TarInfo('../escape.txt')
        invalid.size = 4
        tf.addfile(invalid, io.BytesIO(b'FAIL'))
    with pytest.raises(ValueError, match='unsafe source tar member'):
        _prepare(manifest, tmp_path, work)
    assert not (work / 'build-one/source').exists()

    with tarfile.open(archive, 'w') as tf:
        valid = tarfile.TarInfo('safe.txt')
        valid.size = 4
        tf.addfile(valid, io.BytesIO(b'GOOD'))
    _prepare(manifest, tmp_path, work)
    assert (work / 'build-one/source/safe.txt').read_bytes() == b'GOOD'
