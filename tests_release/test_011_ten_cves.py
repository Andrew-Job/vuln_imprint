"""Regression contract for the ten CVE records added for pre-alpha v0.1.1.

These tests validate archived real-binary evidence and machine-code source
integrity, not native YARA-X execution or independently reviewed accuracy.
"""
import hashlib
import json
import re
from pathlib import Path

import pytest

from factory.patterns import Pattern
from tools.production_db import validate_source_pack

REPO = Path(__file__).resolve().parents[1]
SAMPLES = REPO / 'docs/research/binary-first-0.1.1'
RECORDS = {
    'CVE-2019-7317': 2,
    'CVE-2023-52356': 2,
    'CVE-2024-7006': 1,
    'CVE-2025-9900': 3,
    'CVE-2026-24515': 1,
    'CVE-2026-50219': 1,
    'CVE-2026-56131': 1,
    'CVE-2026-56406': 1,
}
FIRST_TWO = {'CVE-2025-64505': 4, 'CVE-2025-64506': 3}


@pytest.mark.parametrize(('cve', 'patterns_expected'),
                         [*RECORDS.items(), *FIRST_TWO.items()])
def test_011_source_pack_and_canonical_rules(cve, patterns_expected):
    base = REPO / 'signatures' / cve
    pack = json.loads((base / 'pack.json').read_text(encoding='utf-8'))
    assert pack['cve'] == cve
    validate_source_pack(pack,
                         base / 'rules-exec.yar',
                         packfile=base / 'pack.json')
    assert all(record['channel'] == 'production' for record in pack['records'])
    rules = [rule for rec in pack['records'] for rule in rec['rules']]
    assert len(rules) == patterns_expected
    assert all(
        rule['length'] >= 28 and rule['fixed_bytes'] >= 24 for rule in rules)


@pytest.mark.parametrize('cve', RECORDS)
def test_011_reference_evidence_is_bound_to_source(cve):
    base = REPO / 'signatures' / cve
    pack = json.loads((base / 'pack.json').read_text(encoding='utf-8'))
    patterns = [
        Pattern.from_hex(rule['hex'])
        for rec in pack['records']
        for rule in rec['rules']
    ]
    manifest = json.loads(
        (SAMPLES / f'{cve}.samples.json').read_text(encoding='utf-8'))
    evidence = json.loads((SAMPLES / 'evidence' /
                           f'{cve}.reference.json').read_text(encoding='utf-8'))
    assert manifest['cve'] == evidence['cve'] == cve
    assert evidence['status'] == 'PASS_PRELIMINARY'
    assert evidence['production_admission'] is False
    assert evidence['native_yara_x_executed'] is False
    assert evidence['pattern_count'] == len(patterns)
    actual = hashlib.sha256('\n'.join(
        p.to_hex() for p in patterns).encode('ascii')).hexdigest()
    assert actual == evidence['patterns_sha256']
    assert evidence['counts']['affected'] >= 1
    assert evidence['counts']['fixed'] >= 1
    assert evidence['counts']['unrelated'] >= 1
    assert len(manifest['samples']) == len(evidence['results'])
    for specimen, result in zip(manifest['samples'], evidence['results']):
        assert specimen['id'] == result['id']
        assert specimen['sha256'] == result['sha256']
        assert specimen['label'] == result['label']
        assert result['passed'] is True
        assert result['matched'] == (specimen['label'] == 'affected')
        assert all(hit['file_offset'] >= 0 for hit in result['matches'])


def test_011_total_new_records_and_patterns():
    assert len(RECORDS) + len(FIRST_TWO) == 10
    assert sum(RECORDS.values()) + sum(FIRST_TWO.values()) == 19


@pytest.mark.parametrize('relpath', [
    'README.md',
    'CONTRIBUTING.md',
    'signatures/README.md',
    'docs/CREATING_AND_VALIDATING_CVE_MASKS.md',
    'docs/research/binary-first-0.1.1/README.md',
])
def test_011_documentation_relative_links_resolve(relpath):
    path = REPO / relpath
    content = path.read_text(encoding='utf-8')
    for target in re.findall(r'(?<!!)\[[^\]]+\]\(([^)]+)\)', content):
        if re.match(r'^(?:https?://|mailto:)', target):
            continue
        relative = target.split('#', 1)[0]
        if relative:
            assert (path.parent /
                    relative).exists(), f'{relpath}: broken link {relative}'
