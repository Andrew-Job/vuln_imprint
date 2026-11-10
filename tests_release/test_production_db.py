"""Offline DB integrity tests; these do not claim CVE detector correctness."""
import json
import tarfile
from pathlib import Path

import pytest

from factory.signature_identity import new_record_id, record_sha256
from factory.yara_engine import source_from_packs
from tools.production_db import (review_cases, ReleaseRejected, verify_release,
                                 sha256, validate_case, validate_source_pack)

CVE = 'CVE-2026-12345'
PLATFORM = {
    'os': 'linux',
    'format': 'ELF',
    'arch': 'x86-64',
    'bits': 64,
    'abi': 'sysv'
}


def test_cannot_publish_zero_packs(tmp_path):
    cases = tmp_path / 'cases'
    cases.mkdir()
    with pytest.raises(ReleaseRejected, match='requires >=1000'):
        review_cases(cases, Path('/usr/bin/true'), min_cves=1000)
    assert not (tmp_path / 'out').exists()


def _record(cve=CVE, *, channel='production', pattern=None):
    pattern = pattern or ' '.join(['90'] * 28)
    return {
        'record_id':
            new_record_id(cve),
        'channel':
            channel,
        'source_type':
            'manual',
        'platform':
            dict(PLATFORM),
        'rules': [{
            'id': 'p0',
            'hex': pattern,
            'length': len(pattern.split()),
            'fixed_bytes': sum('?' not in token for token in pattern.split())
        }],
    }


def _pack(cve=CVE, *, channel='production', pattern=None):
    return {
        'schema_version': 3,
        'cve': cve,
        'records': [_record(cve, channel=channel, pattern=pattern)]
    }


def test_only_test_and_production_channels_are_allowed(tmp_path):
    pack = _pack(channel='candidate')
    case = tmp_path / 'case'
    case.mkdir()
    (case / 'pack.json').write_text(json.dumps(pack))
    rulefile = case / 'rules-exec.yar'
    rulefile.write_text('')
    with pytest.raises(ReleaseRejected, match='test or production'):
        validate_source_pack(pack, rulefile, packfile=case / 'pack.json')


def dummy_db(path):
    """Create a metadata-only fixture that satisfies the DB integrity schema."""
    path.mkdir()
    record_data = _record(CVE)
    record = {
        'cve': CVE,
        'record_id': record_data['record_id'],
        'record_sha256': record_sha256(record_data),
        'channel': 'production',
        'platform': dict(PLATFORM),
        'pattern_count': 1,
        'pack_sha256': 'a' * 64,
        'rules_sha256': 'b' * 64,
    }
    index = {
        'schema_version': 2,
        'name': 'VulnImprint DB',
        'channel': 'production',
        'profile': {
            'os': 'linux',
            'format': 'ELF',
            'arch': 'x86-64',
            'bits': 64,
            'abi': 'sysv'
        },
        'record_count': 1,
        'pattern_count': 1,
        'cve_count': 1,
        'entries': [record],
    }
    report = {
        'schema_version': 1,
        'channel': 'production',
        'record_count': 1,
        'pattern_count': 1,
        'cve_count': 1,
        'records': [record]
    }
    (path / 'database.yarc').write_bytes(b'not actually compiled')
    (path / 'database.yar').write_text('rule fixture {}')
    (path / 'index.json').write_text(json.dumps(index))
    (path / 'database-report.json').write_text(json.dumps(report))
    files = {p.name: sha256(p) for p in path.iterdir()}
    manifest = {
        'schema_version': 3,
        'artifacts': files,
        'cve_count': 1,
        'record_count': 1,
        'profile': 'linux-elf64-x86_64-sysv',
        'channel': 'production',
        'engine': {
            'name': 'yara-x-capi',
            'version': '1.23.0',
            'serialized_rules_format': 'yara-x'
        },
    }
    (path / 'manifest.json').write_text(json.dumps(manifest))
    (path / 'SHA256SUMS').write_text(''.join(
        f'{digest}  {name}\n' for name, digest in sorted(files.items())))
    return path


def _rehash_db(database):
    manifest_path = database / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    for name in manifest['artifacts']:
        manifest['artifacts'][name] = sha256(database / name)
    manifest_path.write_text(json.dumps(manifest))
    (database / 'SHA256SUMS').write_text(''.join(
        f'{digest}  {name}\n'
        for name, digest in sorted(manifest['artifacts'].items())))


def test_index_channel_must_match_production_manifest(tmp_path):
    database = dummy_db(tmp_path / 'db')
    index_path = database / 'index.json'
    index = json.loads(index_path.read_text())
    index['channel'] = 'test'
    index_path.write_text(json.dumps(index))
    _rehash_db(database)
    with pytest.raises(ReleaseRejected, match='index version, channel'):
        verify_release(database)


def test_sha256sums_disagreement_rejected(tmp_path):
    database = dummy_db(tmp_path / 'db')
    (database /
     'SHA256SUMS').write_text('00' + (database / 'SHA256SUMS').read_text()[2:])
    with pytest.raises(ReleaseRejected, match='SHA256SUMS'):
        verify_release(database)


def test_forged_fixed_byte_strength_is_rejected(tmp_path):
    case = tmp_path / CVE
    case.mkdir()
    source = case / 'rules-exec.yar'
    source.write_text('rule dummy { condition: true }\n')
    fake_pattern = ' '.join(['??'] * 64)
    pack = _pack(pattern=fake_pattern)
    pack['records'][0]['rules'][0]['length'] = 64
    pack['records'][0]['rules'][0]['fixed_bytes'] = 64
    pack_path = case / 'pack.json'
    pack_path.write_text(json.dumps(pack))
    with pytest.raises(ReleaseRejected, match='length/fixed_bytes mismatch'):
        validate_source_pack(pack, source, packfile=pack_path)
    pack['records'][0]['rules'][0]['fixed_bytes'] = 0
    with pytest.raises(ReleaseRejected, match='weak pattern'):
        validate_source_pack(pack, source, packfile=pack_path)


def test_release_contents_binds_embedded_database_and_download_bytes(tmp_path):
    from tools.release_approval import make_contents, verify_contents

    database = dummy_db(tmp_path / 'db')
    product = tmp_path / 'vulnimprint-linux-x86_64.tar.gz'

    def make_product(directory):
        with tarfile.open(product, 'w:gz') as archive:
            for file in sorted(directory.iterdir()):
                archive.add(file,
                            arcname='vulnimprint/share/vulnimprint/db/' +
                            file.name)

    make_product(database)
    sbom = tmp_path / 'SBOM.spdx.json'
    sbom.write_text('{"spdxVersion": "SPDX-2.3"}')
    contents = make_contents(database, 'v0.1.0', 'c' * 40, [product, sbom])
    assert [item['cve'] for item in contents['cves']] == [CVE]
    assert contents['record_count'] == 1
    statement_path = tmp_path / 'release-contents.json'
    statement_path.write_text(json.dumps(contents))
    assert verify_contents(statement_path, tmp_path)['record_count'] == 1

    product.write_bytes(b'tampered')
    with pytest.raises(ReleaseRejected, match='digest mismatch'):
        verify_contents(statement_path, tmp_path)

    other = tmp_path / 'other'
    other.mkdir()
    import shutil
    shutil.copytree(database, other, dirs_exist_ok=True)
    alt_index = json.loads((other / 'index.json').read_text())
    alt_index['entries'][0]['rules_sha256'] = 'e' * 64
    (other / 'index.json').write_text(json.dumps(alt_index))
    alt_report = json.loads((other / 'database-report.json').read_text())
    alt_report['records'] = alt_index['entries']
    (other / 'database-report.json').write_text(json.dumps(alt_report))
    _rehash_db(other)
    make_product(other)
    contents['artifacts'][product.name] = sha256(product)
    statement_path.write_text(json.dumps(contents))
    with pytest.raises(ReleaseRejected, match='does not bind embedded DB'):
        verify_contents(statement_path, tmp_path)


def test_review_requires_matching_cve_source(tmp_path):
    cases = tmp_path / 'cases'
    case = cases / CVE
    case.mkdir(parents=True)
    git = tmp_path / 'validated'
    git.mkdir()
    canonical = git / CVE
    canonical.mkdir()
    pack = _pack()
    source = source_from_packs([pack])
    for directory in (case, canonical):
        (directory / 'pack.json').write_text(json.dumps(pack))
        (directory / 'rules-exec.yar').write_text(source)
        (directory / 'reviewed-evidence.json').write_text('{}')
    scanner = tmp_path / 'scanner'
    scanner.write_text('#!/bin/sh\nexit 0\n')
    scanner.chmod(0o755)
    with pytest.raises(ReleaseRejected,
                       match='mismatched evidence schema or CVE'):
        review_cases(cases, scanner, signatures=git)


def test_unknown_corpus_cve_cannot_be_auto_published(tmp_path):
    cases = tmp_path / 'cases'
    case = cases / CVE
    case.mkdir(parents=True)
    (case / 'pack.json').write_text(json.dumps(_pack()))
    canonical = tmp_path / 'validated'
    canonical.mkdir()
    with pytest.raises(ReleaseRejected,
                       match='Git signature / reviewed corpus CVE mismatch'):
        review_cases(cases, Path('/usr/bin/true'), signatures=canonical)
