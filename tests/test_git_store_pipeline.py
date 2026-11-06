"""Offline Git acquisition + real object builds + reproducible CAS storage test.

Synthetic code: only validates infrastructure, not any CVE-specific signature.
"""
import hashlib
import json
import subprocess
from pathlib import Path
import pytest
from factory.git_source import get_git_source
from factory.artifact_store import ArtifactStore
from factory.pipeline import run, reference_scan


def cmd(*args, cwd):
    return subprocess.run([str(a) for a in args],
                          cwd=cwd,
                          check=True,
                          capture_output=True,
                          text=True).stdout.strip()


def test_git_acquire_build_contrastive_scan_and_cas(tmp_path):
    repo = tmp_path / 'upstream'
    repo.mkdir()
    cmd('git', 'init', '-q', repo, cwd=tmp_path)
    cmd('git', 'config', 'user.name', 'Test', cwd=repo)
    cmd('git', 'config', 'user.email', 'test@example.org', cwd=repo)
    source = '''extern int helper(int);
__attribute__((noinline)) int vulnerable_function(int x) {
 int y = x < 11 ? x*13 : x-7;
 if (x > 19) return helper(x) + y;
 return y;
}
'''
    (repo / 'entry.c').write_text(source)
    cmd('git', 'add', 'entry.c', cwd=repo)
    cmd('git', 'commit', '-qm', 'affected', cwd=repo)
    bad = cmd('git', 'rev-parse', 'HEAD', cwd=repo)
    (repo / 'entry.c').write_text(source.replace('x < 11', 'x < 9'))
    cmd('git', 'commit', '-qam', 'fixed', cwd=repo)
    good = cmd('git', 'rev-parse', 'HEAD', cwd=repo)
    host = tmp_path / 'host.c'
    host.write_text(
        '''int vulnerable_function(int); int helper(int x){return x*5;}
int main(void){return vulnerable_function(24)==0;}
''')
    # Ensure a moving branch is not silently treated as a reproducible source.
    with pytest.raises(ValueError):
        get_git_source({'git': str(repo), 'commit': 'HEAD'}, tmp_path / 'work')
    builds = []
    samples = []
    for label, commit in [('affected', bad), ('fixed', good)]:
        job = label + '-gcc-o2'
        builds.append({
            'name':
                job,
            'artifacts': ['*.o', 'host'],
            'source': {
                'git': str(repo),
                'commit': commit
            },
            'commands': [[
                'gcc', '-O2', '-g', '-fno-pie', '-c', '{source_dir}/entry.c',
                '-o', '{workspace}/entry.o'
            ],
                         [
                             'gcc', '-O2', '-no-pie',
                             str(host), '{workspace}/entry.o', '-o',
                             '{workspace}/host'
                         ], ['strip', '{workspace}/host']]
        })
        for name, role, split in [('entry.o', 'obj', 'train'),
                                  ('host', 'host', 'holdout')]:
            samples.append({
                'id': label + '_' + role,
                'label': label,
                'split': split,
                'path': '{work}/build-' + job + '/' + name,
                'label_basis': 'verified_synthetic',
                'origin': 'offline_git',
                'version': commit[:12],
                'toolchain': 'gcc -O2',
                'profile': {
                    'os': 'linux',
                    'arch': 'x86_64',
                    'abi': 'sysv',
                    'compiler': 'gcc',
                    'opt': 'O2'
                }
            })
    spec = {
        'schema_version': 1,
        'cve': 'CVE-2099-45678',
        'builds': builds,
        'hints': {
            'symbols': ['vulnerable_function']
        },
        'mining': {
            'min_bytes': 16,
            'min_fixed': 14,
            'min_instructions': 3,
            'max_rules': 4
        },
        'samples': samples
    }
    manifest = tmp_path / 'fixture.json'
    manifest.write_text(json.dumps(spec))
    report = run(manifest, tmp_path / 'result', store=tmp_path / 'store')
    assert report['metrics']['train'] == {'TP': 1, 'TN': 1}, report
    assert report['metrics']['holdout'] == {'TP': 1, 'TN': 1}, report
    assert len(report['artifacts']) == 8
    assert sum(r['metadata'].get('role') == 'build_artifact'
               for r in report['artifacts']) == 4
    assert not reference_scan(tmp_path / 'result/pack.json', tmp_path /
                              'result/work/build-fixed-gcc-o2/host')['detected']
    cas = ArtifactStore(tmp_path / 'store')
    assert all(cas.verify(r) for r in report['artifacts'])
    assert {
        r['metadata']['build']['source']['commit'] for r in report['artifacts']
    } == {bad, good}
    assert (tmp_path / 'result/rules-exec.yar').exists()
    for variant, commit in [('affected', bad), ('fixed', good)]:
        source_info = json.loads(
            (tmp_path / 'result/work' / ('build-' + variant + '-gcc-o2') /
             'source-provenance.json').read_text())
        assert source_info['commit'] == commit


def test_cas_deduplicates_blobs_and_detects_tamper(tmp_path):
    store = ArtifactStore(tmp_path / 'store')
    src = tmp_path / 'a'
    src.write_bytes(b'example-test')
    a = store.add(src, cve='CVE-2099-12345', specimen_id='one')
    b = store.add(src, cve='CVE-2099-54321', specimen_id='two')
    assert a['blob']['path'] == b['blob']['path']
    assert len(list((tmp_path / 'store/blobs').rglob('*-*'))) == 0
    assert store.verify(a)
    (tmp_path / 'store' / a['blob']['path']).write_bytes(b'tampered')
    assert not store.verify(b)
