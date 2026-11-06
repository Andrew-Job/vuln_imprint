"""Manual authoring uses production source constraints; these are not CVE validations."""
from pathlib import Path
import json
import pytest
from tools.manual_rules import initialize, check_manual_source, analyze_hex
from tools.production_db import validate_source_pack, ReleaseRejected

PATTERN = ' '.join(f'{x:02X}' for x in range(32))


def make_case(tmp_path):
    path = tmp_path / 'CVE-2022-37434'
    pack = initialize('CVE-2022-37434', [PATTERN], path)
    return path, pack


def test_init_writes_real_yara_rule_but_is_candidate(tmp_path):
    p, pack = make_case(tmp_path)
    source = (p/'rules-exec.yar').read_text()
    assert pack['status'] == 'CANDIDATE_ONLY'
    assert 'rule CVE_2022_37434_ELF64_x86_64' in source
    assert '$v0 = {' in source
    check_manual_source(pack, source)
    with pytest.raises(ReleaseRejected, match='must be approved'):
        validate_source_pack(pack, p/'rules-exec.yar', packfile=p/'pack.json')


def test_reviewer_can_promote_only_matching_source(tmp_path):
    p, pack = make_case(tmp_path)
    pack['status'] = 'CVE_SPECIFIC_VALIDATED'
    source = (p/'rules-exec.yar').read_text().replace('CANDIDATE_ONLY', 'CVE_SPECIFIC_VALIDATED')
    (p/'rules-exec.yar').write_text(source)
    (p/'pack.json').write_text(json.dumps(pack))
    validate_source_pack(pack, p/'rules-exec.yar', packfile=p/'pack.json')
    for bad in ('include "secret.yar"\n'+source,
                source.replace('CVE-2022-37434', 'CVE-2022-37435'),
                source.replace('any of them', 'true').replace(PATTERN, PATTERN[:-2]+'AA'),
                source.replace('rule CVE_2022_37434_ELF64_x86_64', 'rule unrelated')):
        with pytest.raises(ReleaseRejected):
            check_manual_source(pack, bad)


def test_manual_rejects_weak_bytesequence_and_malformed_hex(tmp_path):
    with pytest.raises(ReleaseRejected, match='too-short'):
        initialize('CVE-2022-37434', ['AA BB CC'], tmp_path/'x')
    with pytest.raises(ReleaseRejected, match='byte tokens'):
        initialize('CVE-2022-37434', ['AA BB [1-10] 01'], tmp_path/'y')
    assert analyze_hex(' '.join(['??']*4+['AB']*28))==(32,28)


def test_manual_rejects_extra_regex_or_literal_string(tmp_path):
    p, pack = make_case(tmp_path)
    src = (p/'rules-exec.yar').read_text().replace('  condition:', '    $text = "evil"\n  condition:')
    with pytest.raises(ReleaseRejected,match='approved hex'):
        check_manual_source(pack, src)


def test_manual_rejects_noncanonical_rule_condition(tmp_path):
    p, pack=make_case(tmp_path)
    src=(p/'rules-exec.yar').read_text().replace('any of them','true')
    with pytest.raises(ReleaseRejected, match='condition must be exactly'):
        check_manual_source(pack,src)
