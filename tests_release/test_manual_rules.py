"""Manual authoring creates CVE-owned records with test/production channels."""
import json

import pytest

from tools.manual_rules import initialize, check_manual_source, analyze_hex
from tools.production_db import validate_source_pack, ReleaseRejected

PATTERN = ' '.join(f'{x:02X}' for x in range(32))


def make_case(tmp_path, *, channel='test', record_key='default'):
    path = tmp_path / 'CVE-2022-37434'
    pack = initialize('CVE-2022-37434', [PATTERN],
                      path,
                      channel=channel,
                      record_key=record_key)
    return path, pack


def test_init_writes_cve_owned_test_record_and_real_yara_rule(tmp_path):
    path, pack = make_case(tmp_path)
    source = (path / 'rules-exec.yar').read_text()
    record = pack['records'][0]
    assert pack['schema_version'] == 3
    assert pack['cve'] == 'CVE-2022-37434'
    assert record['channel'] == 'test'
    assert f'rule {record["record_id"]}' in source
    assert 'cve = "CVE-2022-37434"' in source
    assert 'cves =' not in source
    assert '$v0 = {' in source
    check_manual_source(pack, source)
    validate_source_pack(pack,
                         path / 'rules-exec.yar',
                         packfile=path / 'pack.json')


def test_multiple_records_for_same_cve_have_independent_ids(tmp_path):
    first = make_case(tmp_path / 'first', record_key='first')[1]
    second = make_case(tmp_path / 'second', record_key='second')[1]
    assert first['cve'] == second['cve']
    assert first['records'][0]['record_id'] != second['records'][0]['record_id']


def test_production_channel_is_explicit_and_source_integrity_is_enforced(
        tmp_path):
    path, pack = make_case(tmp_path, channel='production')
    record = pack['records'][0]
    assert record['channel'] == 'production'
    source = (path / 'rules-exec.yar').read_text()
    for bad in (
            'include "secret.yar"\n' + source,
            source.replace('CVE-2022-37434', 'CVE-2022-37435'),
            source.replace('any of them',
                           'true').replace(PATTERN, PATTERN[:-2] + 'AA'),
            source.replace('rule ' + record['record_id'], 'rule unrelated'),
    ):
        with pytest.raises(ReleaseRejected):
            check_manual_source(pack, bad)


def test_manual_rejects_weak_bytesequence_and_malformed_hex(tmp_path):
    with pytest.raises(ReleaseRejected, match='too-short'):
        initialize('CVE-2022-37434', ['AA BB CC'], tmp_path / 'x')
    with pytest.raises(ReleaseRejected, match='byte tokens'):
        initialize('CVE-2022-37434', ['AA BB [1-10] 01'], tmp_path / 'y')
    assert analyze_hex(' '.join(['??'] * 4 + ['AB'] * 28)) == (32, 28)


def test_manual_rejects_extra_regex_or_literal_string(tmp_path):
    path, pack = make_case(tmp_path)
    source = (path / 'rules-exec.yar').read_text().replace(
        '  condition:', '    $text = "evil"\n  condition:')
    with pytest.raises(ReleaseRejected, match='canonical CVE pack'):
        check_manual_source(pack, source)


def test_manual_rejects_noncanonical_rule_condition(tmp_path):
    path, pack = make_case(tmp_path)
    source = (path / 'rules-exec.yar').read_text().replace(
        'any of them', 'true')
    with pytest.raises(ReleaseRejected, match='canonical CVE pack'):
        check_manual_source(pack, source)
