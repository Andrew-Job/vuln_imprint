"""Production release composition contracts for CVE-owned DB records."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import production_db
from tools.production_db import ReleaseRejected
from tools.release_approval import _validate_entries, _validate_statement

ROOT = Path(__file__).resolve().parents[1]


def _snapshot():
    source = ROOT / 'signatures'
    catalog = sorted(
        path.name for path in source.glob('CVE-*') if path.is_dir())
    packs = [
        json.loads(path.read_text())
        for path in sorted(source.glob('CVE-*/pack.json'))
    ]
    return catalog, packs


def _scanner_stub(tmp_path, monkeypatch):
    scanner = tmp_path / 'scanner'
    scanner.write_text('#!/bin/sh\nexit 1\n')
    scanner.chmod(0o755)
    _catalog, packs = _snapshot()
    record_count = sum(len(pack['records']) for pack in packs)
    operations = []

    def native(argv, **_kwargs):
        operations.append(argv[1])
        if argv[1] == 'compile':
            source = Path(argv[argv.index('--rules') + 1]).read_text()
            for pack in packs:
                assert f'cve = "{pack["cve"]}"' in source
                for record in pack['records']:
                    assert f'rule {record["record_id"]}' in source
            assert source.count('rule VI_') == record_count
            Path(argv[argv.index('--output') +
                      1]).write_bytes(b'test compilation')
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        if argv[1] == 'verify':
            return SimpleNamespace(returncode=0,
                                   stdout=json.dumps({
                                       'engine': 'yara-x',
                                       'rules': record_count
                                   }),
                                   stderr='')
        raise AssertionError(argv)

    monkeypatch.setattr(production_db.subprocess, 'run', native)
    return scanner, operations


def _rehash_manifest(output):
    manifest_file = output / 'manifest.json'
    manifest = json.loads(manifest_file.read_text())
    manifest['artifacts']['index.json'] = production_db.sha256(output /
                                                               'index.json')
    manifest['artifacts']['database-report.json'] = production_db.sha256(
        output / 'database-report.json')
    production_db.write_json(manifest_file, manifest)
    (output / 'SHA256SUMS').write_text(''.join(
        f'{digest}  {name}\n'
        for name, digest in sorted(manifest['artifacts'].items())))


def test_git_tree_release_assembles_all_production_records(
        tmp_path, monkeypatch):
    scanner, operations = _scanner_stub(tmp_path, monkeypatch)
    output = tmp_path / 'database'
    result = production_db.assemble_git_tree(ROOT / 'signatures', output,
                                             scanner)
    catalog, packs = _snapshot()
    expected_records = [(pack['cve'], record['record_id'])
                        for pack in packs
                        for record in pack['records']
                        if record['channel'] == 'production']
    assert result['source_cve_count'] == len(catalog)
    assert result['cve_count'] == len({cve for cve, _ in expected_records})
    assert result['record_count'] == len(expected_records)
    assert operations == ['compile', 'verify']

    index = json.loads((output / 'index.json').read_text())
    assert index['source_cves'] == catalog
    assert index['excluded_from_channel_cves'] == sorted(
        set(catalog) - {cve for cve, _ in expected_records})
    assert index['record_count'] == len(expected_records)
    assert index['pattern_count'] == sum(
        len(record['rules'])
        for pack in packs
        for record in pack['records']
        if record['channel'] == 'production')
    assert {(entry['cve'], entry['record_id']) for entry in index['entries']
           } == set(expected_records)
    assert production_db.verify_release(
        output)['cve_count'] == index['cve_count']
    statement = _validate_entries(index)
    assert _validate_statement(statement, index['cve_count'],
                               index['record_count']) == statement


def test_index_channel_cannot_be_changed_by_rehashing_payload(
        tmp_path, monkeypatch):
    scanner, _operations = _scanner_stub(tmp_path, monkeypatch)
    output = tmp_path / 'database'
    production_db.assemble_git_tree(ROOT / 'signatures', output, scanner)
    index_file = output / 'index.json'
    index = json.loads(index_file.read_text())
    index['channel'] = 'test'
    production_db.write_json(index_file, index)
    _rehash_manifest(output)
    with pytest.raises(ReleaseRejected, match='index version, channel'):
        production_db.verify_release(output)


def test_release_statement_preserves_independent_record_ownership():
    from factory.signature_identity import new_record_id, record_sha256
    cve_a, cve_b = 'CVE-2026-12345', 'CVE-2026-67890'
    entries = []
    for cve, key in ((cve_a, 'first'), (cve_a, 'second'),
                     (cve_b, 'duplicate-pattern')):
        entries.append({
            'cve':
                cve,
            'record_id':
                new_record_id(cve, key),
            'record_sha256':
                record_sha256({
                    'record_id':
                        new_record_id(cve, key),
                    'channel':
                        'production',
                    'source_type':
                        'manual',
                    'platform': {
                        'os': 'linux',
                        'format': 'ELF',
                        'arch': 'x86-64',
                        'bits': 64,
                        'abi': 'sysv'
                    },
                    'rules': [{
                        'id': key + '-pattern',
                        'hex': '90 ' * 27 + '90',
                        'length': 28,
                        'fixed_bytes': 28
                    }],
                }),
            'channel':
                'production',
            'pattern_count':
                1,
            'pack_sha256':
                'a' * 64,
            'rules_sha256':
                'b' * 64,
        })
    entries.sort(key=lambda row: (row['cve'], row['record_id']))
    index = {
        'channel': 'production',
        'cve_count': 2,
        'record_count': 3,
        'entries': entries
    }
    statement = _validate_entries(index)
    assert len(statement) == 2
    assert len(statement[0]['records']) == 2
    assert len(statement[1]['records']) == 1
    assert _validate_statement(statement, 2, 3) == statement


def test_database_report_cannot_conflict_with_index_after_rehash(
        tmp_path, monkeypatch):
    scanner, _operations = _scanner_stub(tmp_path, monkeypatch)
    output = tmp_path / 'database'
    production_db.assemble_git_tree(ROOT / 'signatures', output, scanner)
    report_file = output / 'database-report.json'
    report = json.loads(report_file.read_text())
    report['records'][0]['pack_sha256'] = 'a' * 64
    production_db.write_json(report_file, report)
    _rehash_manifest(output)
    with pytest.raises(ReleaseRejected,
                       match='database report and index disagree'):
        production_db.verify_release(output)
