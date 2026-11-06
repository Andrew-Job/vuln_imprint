import json

import pytest

from factory.database import load_included_packs, merge_packs
from factory.signature_identity import new_record_id


def test_test_and_production_channels_select_records_without_quality_states(
        tmp_path):
    root = tmp_path / 'packs'
    root.mkdir()
    case = root / 'CVE-2022-12345'
    case.mkdir()
    cve = 'CVE-2022-12345'
    pack = {
        'schema_version':
            3,
        'cve':
            cve,
        'records': [
            {
                'record_id': new_record_id(cve, 'production-record'),
                'channel': 'production',
                'source_type': 'manual',
                'platform': {
                    'os': 'linux',
                    'format': 'ELF',
                    'arch': 'x86-64',
                    'bits': 64,
                    'abi': 'sysv'
                },
                'rules': [{
                    'id': 'prod',
                    'hex': '01 02 03 04'
                }],
            },
            {
                'record_id': new_record_id(cve, 'test-record'),
                'channel': 'test',
                'source_type': 'manual',
                'platform': {
                    'os': 'linux',
                    'format': 'ELF',
                    'arch': 'x86-64',
                    'bits': 64,
                    'abi': 'sysv'
                },
                'rules': [{
                    'id': 'test',
                    'hex': '05 06 07 08'
                }],
            },
        ],
    }
    (case / 'pack.json').write_text(json.dumps(pack))

    test_db = tmp_path / 'test-db'
    test_index = merge_packs([case], test_db, channel='test')
    assert test_index['cve_count'] == 1
    assert test_index['record_count'] == 2
    assert {record['channel'] for record in test_index['entries']
           } == {'test', 'production'}
    assert len(load_included_packs(test_db)) == 2

    production_db = tmp_path / 'production-db'
    production_index = merge_packs([case], production_db, channel='production')
    assert production_index['cve_count'] == 1
    assert production_index['record_count'] == 1
    assert [record['channel'] for record in production_index['entries']
           ] == ['production']
    assert len(load_included_packs(production_db)) == 1

    test_index_path = test_db / 'index.json'
    corrupted = json.loads(test_index_path.read_text())
    corrupted['channel'] = 'production'
    test_index_path.write_text(json.dumps(corrupted))
    with pytest.raises(ValueError, match='inconsistent'):
        load_included_packs(test_db)
