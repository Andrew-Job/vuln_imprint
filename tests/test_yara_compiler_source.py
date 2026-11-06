from factory.yara_engine import source_from_packs
from factory.patterns import Pattern
from factory.signature_identity import new_record_id


def test_yara_exec_region_source_has_no_file_offset_conditions():
    cve = 'CVE-2099-99999'
    record_id = new_record_id(cve)
    sample = {
        'schema_version':
            3,
        'cve':
            cve,
        'records': [{
            'record_id':
                record_id,
            'channel':
                'test',
            'source_type':
                'factory',
            'platform': {
                'os': 'linux',
                'format': 'ELF',
                'arch': 'x86-64',
                'bits': 64,
                'abi': 'sysv'
            },
            'rules': [{
                'id': 'CVE-2099-99999-v00',
                'hex': Pattern.from_hex('48 8b ?? 33 44 55 66').to_hex()
            }]
        }]
    }
    text = source_from_packs([sample])
    assert 'rule ' + record_id in text
    assert 'cve = "CVE-2099-99999"' in text
    assert 'channel = "test"' in text
    assert '{ 48 8B ?? 33 44 55 66 }' in text
    assert 'any of them' in text
    assert 'uint32(' not in text
    assert 'import "elf"' not in text
    assert 'cves =' not in text
