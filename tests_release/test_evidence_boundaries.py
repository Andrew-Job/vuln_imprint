"""Holdout independence, acquisition transport, and provenance contracts."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from factory.evidence_isolation import is_independent_holdout
from factory.git_source import get_git_source
from tools import production_db


def _sample(tmp_path: Path, name: str, data: bytes, split: str,
            lineage: str | None):
    file = tmp_path / name
    file.write_bytes(data)
    return SimpleNamespace(path=file,
                           split=split,
                           provenance={'lineage': lineage} if lineage else {})


def test_holdout_sha_overlap_is_not_independent(tmp_path):
    samples = [
        _sample(tmp_path, 'train', b'old bytes', 'train', 'build-A'),
        _sample(tmp_path, 'holdout_pos', b'old bytes', 'holdout', 'new-name'),
        _sample(tmp_path, 'holdout_fixed', b'fixed', 'holdout', 'fixed-B')
    ]
    assert not is_independent_holdout(samples)


def test_holdout_requires_lineage_for_every_sample(tmp_path):
    samples = [
        _sample(tmp_path, 'train', b'train', 'train', 'build-A'),
        _sample(tmp_path, 'holdout_pos', b'positive', 'holdout',
                'independent-A'),
        _sample(tmp_path, 'holdout_fixed', b'fixed', 'holdout', None)
    ]
    assert not is_independent_holdout(samples)


def test_holdout_rejects_dev_exposure_and_accepts_distinct(tmp_path):
    samples = [
        _sample(tmp_path, 'train', b'train', 'train', 'train-A'),
        _sample(tmp_path, 'dev', b'dev', 'dev', 'dev-A'),
        _sample(tmp_path, 'holdout_pos', b'positive', 'holdout',
                'independent-A'),
        _sample(tmp_path, 'holdout_fixed', b'fixed', 'holdout', 'independent-B')
    ]
    assert is_independent_holdout(samples)
    samples[-1].provenance['lineage'] = 'dev-A'
    assert not is_independent_holdout(samples)


@pytest.mark.parametrize('url', [
    'git@github.com:org/repo.git',
    'ssh://git@github.com/org/repo.git',
    'git://github.com/org/repo.git',
    'ext::sh -c touch /tmp/untrusted',
    'https://user:secret@github.com/org/repo.git',
    'relative/path',
])
def test_git_acquisition_rejects_untrusted_transports(tmp_path, url):
    with pytest.raises(ValueError, match='source|transport|HTTPS|path|Git'):
        get_git_source({'git': url, 'commit': 'a' * 40}, tmp_path)


def test_build_provenance_identity_must_bind_exact_reviewed_sample():
    row = {
        'binary_kind': 'source_built_elf',
        'artifact_role': 'host_0',
        'source_commit': 'a' * 40,
        'sha256': 'b' * 64,
        'build_profile': {
            'compiler_family': 'gcc',
            'compiler_version': '11.99.0',
            'compiler_major': 11,
            'compiler_binary_sha256': 'c' * 64,
            'compiler_target': 'x86_64-linux-gnu',
            'optimization': '-O2'
        },
        'build_provenance': {
            'schema_version': 1,
            'source': {
                'type': 'git',
                'commit': 'a' * 40
            },
            'source_provenance_sha256': 'f' * 64,
            'toolchain': {
                'family': 'gcc',
                'version': '11.99.0',
                'binary_sha256': 'c' * 64,
                'target': 'x86_64-linux-gnu',
                'optimization': '-O2',
                'executable': '/usr/bin/gcc-11'
            },
            'artifacts': {
                'module.o': 'd' * 64,
                'libcomponent.a': 'e' * 64,
                'host_0': 'b' * 64,
                'host_1': 'a' * 64
            },
            'commands': [['/usr/bin/gcc-11', '-O2', 'main.c', '-o', 'host_0']]
        }
    }
    assert production_db.validate_reviewed_toolchain(
        row, 'CVE-2099-12345')['binary_sha256'] == 'c' * 64
    tampered = {**row, 'sha256': 'd' * 64}
    with pytest.raises(production_db.ReleaseRejected, match='bind the sample'):
        production_db.validate_reviewed_toolchain(tampered, 'CVE-2099-12345')


def test_static_product_requires_cryptographic_upstream_proof(tmp_path):
    path = tmp_path / 'static-elf'
    path.write_bytes(b'machine bytes')
    with pytest.raises(production_db.ReleaseRejected, match='signing identity'):
        production_db.verify_third_party_attestation(
            path, {
                'origin':
                    'https://github.com/other/source',
                'attestation_repository':
                    'publisher/project',
                'attestation_signer_workflow':
                    'publisher/project/.github/workflows/release.yml'
            })
