"""Tests compiler-lane generation and CVE evidence validation."""

import pytest

from factory.toolchains import probe_compiler, ToolchainMismatch
from scripts.create_catalog import make_manifest, parse_compiler_lanes
from tools.production_db import ReleaseRejected, validate_reviewed_toolchain

RECORD = (
    'CVE-2099-10001',
    'zlib',
    '1.2.11',
    '1.2.12',
    'deflate.c',
    'deflate',
    'https://example.test/advisory',
)


def test_compiler_name_rejects_executable_paths():
    """The catalog accepts compiler identifiers, not executable paths."""
    with pytest.raises(ToolchainMismatch, match='must be'):
        probe_compiler('/usr/bin/gcc')


def test_generated_manifest_has_full_factorial_build_lanes():
    recipe = make_manifest(RECORD)
    assert len(recipe['builds']) == 16
    assert len(recipe['samples']) == 48
    lanes = {(
        build['profile']['compiler'],
        build['profile']['compiler_major'],
        build['profile']['optimization'],
    ) for build in recipe['builds']}
    assert len(lanes) == 8
    assert {family for family, _, _ in lanes} == {'gcc', 'clang'}
    assert {build['state'] for build in recipe['builds']
           } == {'affected', 'fixed'}


def test_release_evidence_needs_real_versions(monkeypatch):
    good = {
        'compiler_family': 'gcc',
        'compiler_version': '12.3.0',
        'compiler_binary_sha256': 'a' * 64,
        'compiler_target': 'x86_64-linux-gnu',
        'optimization': '-O2',
        'compiler_major': 12,
    }
    monkeypatch.setattr(
        'tools.production_db.probe_compiler',
        lambda *args, **kwargs: {
            'binary_sha256': 'a' * 64,
            'target': 'x86_64-linux-gnu',
        },
    )
    row = {
        'binary_kind': 'source_built_elf',
        'artifact_role': 'host_0',
        'build_profile': good,
        'source_commit': 'a' * 40,
        'sha256': 'c' * 64,
        'build_provenance': {
            'schema_version': 1,
            'source': {
                'type': 'git',
                'commit': 'a' * 40
            },
            'source_provenance_sha256': 'f' * 64,
            'toolchain': {
                'family': 'gcc',
                'version': '12.3.0',
                'binary_sha256': 'a' * 64,
                'target': 'x86_64-linux-gnu',
                'optimization': '-O2',
                'executable': '/usr/bin/gcc-12',
            },
            'artifacts': {
                'module.o': 'b' * 64,
                'libcomponent.a': 'd' * 64,
                'host_0': 'c' * 64,
                'host_1': 'e' * 64,
            },
            'commands': [['/usr/bin/gcc-12', '-O2', 'main.c', '-o', 'host_0']],
        },
    }
    cve = 'CVE-2022-37434'
    assert validate_reviewed_toolchain(row, cve)['version'] == '12.3.0'

    with pytest.raises(ReleaseRejected, match='provenance'):
        validate_reviewed_toolchain({**row, 'build_provenance': None}, cve)
    with pytest.raises(ReleaseRejected, match='bind the sample'):
        validate_reviewed_toolchain({**row, 'sha256': 'd' * 64}, cve)

    wrong_source = {
        **row['build_provenance'],
        'source': {
            'type': 'git',
            'commit': 'e' * 40
        },
    }
    with pytest.raises(ReleaseRejected, match='bind the sample'):
        validate_reviewed_toolchain({
            **row, 'build_provenance': wrong_source
        }, cve)

    wrong_opt = {
        **row['build_provenance'],
        'commands': [['gcc-12', '-O3', '-o', 'host_0']],
    }
    with pytest.raises(ReleaseRejected, match='optimization'):
        validate_reviewed_toolchain({**row, 'build_provenance': wrong_opt}, cve)

    for change in (
        {
            'compiler_version': '12'
        },
        {
            'compiler_major': 13
        },
        {
            'compiler_binary_sha256': 'nope'
        },
        {
            'compiler_family': 'unknown'
        },
    ):
        with pytest.raises(ReleaseRejected):
            validate_reviewed_toolchain(
                {
                    **row, 'build_profile': {
                        **good,
                        **change
                    }
                }, cve)

    # An object-file digest cannot identify the linked executable.
    module_only = {
        **row['build_provenance'],
        'artifacts': {
            **row['build_provenance']['artifacts'],
            'module.o': 'c' * 64,
            'host_0': 'b' * 64,
        },
    }
    with pytest.raises(ReleaseRejected, match='bind the sample'):
        validate_reviewed_toolchain({
            **row, 'build_provenance': module_only
        }, cve)
    with pytest.raises(ReleaseRejected, match='linked host_0/host_1'):
        validate_reviewed_toolchain({**row, 'artifact_role': 'module.o'}, cve)
    with pytest.raises(ReleaseRejected, match='link command'):
        validate_reviewed_toolchain(
            {
                **row,
                'build_provenance': {
                    **row['build_provenance'],
                    'commands': [['echo', '-O2', 'host_0']],
                },
            },
            cve,
        )
    assert validate_reviewed_toolchain(
        {'binary_kind': 'stripped_third_party_executable'}, cve) is None


def test_configurable_compiler_lanes():
    recipe = make_manifest(
        RECORD,
        compiler_lanes=['gcc-15', 'gcc-16', 'clang-22', 'clang-23'],
    )
    lanes = {(build['profile']['compiler'], build['profile']['compiler_major'])
             for build in recipe['builds']}
    assert lanes == {
        ('gcc', 15),
        ('gcc', 16),
        ('clang', 22),
        ('clang', 23),
    }
    for bad in (
        ['gcc-16'],
        ['clang-23'],
        ['gcc-16', 'clang-23', 'gcc-16'],
    ):
        with pytest.raises(ValueError):
            parse_compiler_lanes(bad)
