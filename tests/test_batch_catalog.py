"""Offline checks: ten CVE recipes, immutable source locking and no false success."""
import json
import subprocess
from pathlib import Path
from factory import batch
from scripts.create_catalog import make_manifest

RECORDS = [
    ('CVE-2099-10001', 'zlib', '1.2.11', '1.2.12', 'deflate.c', 'deflate',
     'https://example.test/advisory-1'),
    ('CVE-2099-10002', 'libpng', '1.6.36', '1.6.37', 'png.c', 'png_image_free',
     'https://example.test/advisory-2'),
]


def test_generated_manifest_has_explicit_build_and_sample_controls():
    for item in RECORDS:
        cve = item[0]
        obj = make_manifest(item)
        assert obj['schema_version'] == 1
        assert obj['cve'] == cve
        assert len(obj['builds']) == 16
        assert len(obj['samples']) == 48
        assert {s['label'] for s in obj['samples']} == {'affected', 'fixed'}
        assert {s['split'] for s in obj['samples']
               } == {'train', 'dev', 'regression'}
        lanes = {(b['profile']['compiler'], b['profile']['compiler_major'],
                  b['profile']['optimization']) for b in obj['builds']}
        assert lanes == {(cc, major, opt)
                         for cc, major in (('gcc', 11), ('gcc', 12),
                                           ('clang', 14), ('clang', 15))
                         for opt in ('-O2', '-O3')}
        assert all(
            '--compiler-major' in b['commands'][0] for b in obj['builds'])
        assert all('ref' in job['source'] and 'commit' not in job['source']
                   for job in obj['builds'])


def test_lock_resolves_repeated_tags_once(tmp_path, monkeypatch):
    calls = []

    def mock_ref(url, tag):
        calls.append((url, tag))
        return '3' * 40

    monkeypatch.setattr(batch, 'resolve_git_ref', mock_ref)
    source = tmp_path / 'CVE-2099-10001.json'
    source.write_text(json.dumps(make_manifest(RECORDS[0])))
    locked = tmp_path / 'locked.json'
    data = batch.freeze_manifest(source, locked)
    assert len(calls) == 2
    assert all(job['source']['commit'] == '3' * 40 for job in data['builds'])
    assert all(job['source']['ref'].startswith('v') for job in data['builds'])
    assert locked.exists()


def test_batch_records_acquisition_failures_without_signature(
        tmp_path, monkeypatch):
    root = tmp_path / 'catalog'
    root.mkdir()
    for item in RECORDS:
        (root / (item[0] + '.json')).write_text(json.dumps(make_manifest(item)))

    def unavailable(*args):
        raise subprocess.CalledProcessError(128, ['git', 'ls-remote'])

    monkeypatch.setattr(batch, 'resolve_git_ref', unavailable)
    report = batch.batch_run(root, tmp_path / 'out')
    assert report['requested_cves'] == 2
    assert report['completed_pipeline_cves'] == 0
    assert report['strictly_validated_cves'] == 0
    assert report['native_database']['status'] == 'NO_ADMITTED_PACKS'
    assert all(
        x['status'] == 'BLOCKED_SOURCE_ACQUISITION' for x in report['entries'])
    assert (tmp_path / 'out/batch-report.json').exists()
    assert not list((tmp_path / 'out').rglob('pack.json'))
