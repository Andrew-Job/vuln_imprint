"""Admission-policy regressions, with native matching mocked at the boundary.

These tests do not assert real CVE detection or third-party YARA-X behavior.
"""

import json

import pytest

from tools import production_db

CVE = 'CVE-2026-25646'


def make_case(tmp_path, monkeypatch):
    case = tmp_path / CVE
    case.mkdir()
    pack = case / 'pack.json'
    rules = case / 'rules-exec.yar'
    pack.write_text(json.dumps({'cve': CVE}))
    rules.write_text('rule fake {condition:true}')
    monkeypatch.setattr(production_db, 'validate_source_pack',
                        lambda *a, **kw: None)
    monkeypatch.setattr(
        production_db, 'native_scan', lambda scanner, rulefile, target: {
            'matches': ([{
                'cve': CVE,
                'executable': True
            }] if target.name.startswith('affected-') else [])
        })
    monkeypatch.setattr(
        production_db, 'probe_compiler', lambda *a, **kw: {
            'binary_sha256': 'c' * 64,
            'target': 'x86_64-linux-gnu'
        })
    samples = []

    def add(label, name, lane=None):
        file = case / name
        file.write_bytes(name.encode())
        sample = {
            'id':
                name,
            'path':
                name,
            'sha256':
                production_db.sha256(file),
            'split':
                'independent_holdout',
            'label':
                label,
            'lineage':
                name,
            'label_basis': ('independent_unrelated'
                            if label == 'unrelated' else 'patch_state'),
            'origin':
                'https://example.org/reviewed-source',
            'source_commit':
                'a' * 40,
            'version':
                '1.6.53' if label in ('affected', 'backport') else '1.6.58',
        }
        if label == 'backport':
            sample['patch_commit'] = 'b' * 40
        if lane:
            family, major, optimization = lane
            profile = {
                'family': family,
                'version': f'{major}.0.1',
                'binary_sha256': 'c' * 64,
                'optimization': optimization,
                'target': 'x86_64-linux-gnu',
            }
            sample['binary_kind'] = 'source_built_elf'
            sample['artifact_role'] = 'host_0'
            sample['build_profile'] = {
                'compiler_family': family,
                'compiler_version': profile['version'],
                'compiler_major': major,
                'compiler_binary_sha256': profile['binary_sha256'],
                'compiler_target': profile['target'],
                'optimization': optimization,
            }
            sample['build_provenance'] = {
                'schema_version':
                    1,
                'source_provenance_sha256':
                    'f' * 64,
                'source': {
                    'type': 'git',
                    'commit': sample['source_commit']
                },
                'toolchain': {
                    **profile, 'executable': f'/usr/bin/{family}-{major}'
                },
                'artifacts': {
                    'module.o': 'a' * 64,
                    'libcomponent.a': 'b' * 64,
                    'host_0': sample['sha256'],
                    'host_1': 'd' * 64
                },
                'commands': [[
                    f'/usr/bin/{family}-{major}', optimization, 'main.c', '-o',
                    'host_0'
                ]],
            }
        samples.append(sample)
        return sample

    for family, majors in (('gcc', (11, 12)), ('clang', (14, 15))):
        for major in majors:
            for opt in ('-O2', '-O3'):
                add('affected', f'affected-{family}-{major}-{opt}',
                    (family, major, opt))
                add('fixed', f'fixed-{family}-{major}-{opt}',
                    (family, major, opt))
    add('backport', 'backport-one', ('gcc', 11, '-O2'))
    for n in range(20):
        add('unrelated', f'unrelated-{n}')
    evidence = {
        'schema_version': 2,
        'cve': CVE,
        'quality': 'CVE_SPECIFIC_VALIDATED',
        'rules_sha256': production_db.sha256(rules),
        'pack_sha256': production_db.sha256(pack),
        'training_lineages': ['training-different'],
        'samples': samples,
    }
    (case / 'fake_scanner').write_bytes(b'fake scanner for policy tests only')
    path = case / 'reviewed-evidence.json'
    path.write_text(json.dumps(evidence))
    return case, evidence, path


def test_fixed_lineages_are_independent_of_backport_lineages(
        tmp_path, monkeypatch):
    case, evidence, path = make_case(tmp_path, monkeypatch)
    assert production_db.validate_case(case, case /
                                       'fake_scanner')['counts']['fixed'] == 8
    for sample in evidence['samples']:
        if sample['label'] == 'fixed':
            sample['lineage'] = 'all-fixed-same-source-lineage'
    path.write_text(json.dumps(evidence))
    with pytest.raises(production_db.ReleaseRejected,
                       match='insufficient affected/fixed lineages'):
        production_db.validate_case(case, case / 'fake_scanner')


def test_source_pack_rejects_platform_extra_that_changes_rule_id(tmp_path):
    pack = {
        'schema_version':
            1,
        'cve':
            CVE,
        'status':
            'CVE_SPECIFIC_VALIDATED',
        'platform': {
            'os': 'linux',
            'format': 'ELF',
            'arch': 'x86-64',
            'bits': 64,
            'abi': 'sysv',
            'compiler': 'gcc'
        },
        'rules': [{
            'id': 'first',
            'hex': '90 ' * 32,
            'length': 32,
            'fixed_bytes': 32
        }]
    }
    rulefile = tmp_path / 'rules-exec.yar'
    rulefile.write_text('nonempty source')
    packfile = tmp_path / 'pack.json'
    packfile.write_text(json.dumps(pack))
    with pytest.raises(production_db.ReleaseRejected,
                       match='unsupported or noncanonical platform'):
        production_db.validate_source_pack(pack, rulefile, packfile=packfile)
