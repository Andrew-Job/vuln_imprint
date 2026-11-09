"""Lock source signatures and frozen real-ELF evidence for two new libpng CVEs.

These checks validate previously obtained reference evidence, not a new
execution of YARA-X/Scanner or a substitute for rerunning actual binaries.
"""
import json
from pathlib import Path

import pytest

from tools.production_db import validate_source_pack

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / 'docs' / 'research' / 'libpng-elf64-x86_64'


@pytest.mark.parametrize('cve,pattern_count,offsets', [
    ('CVE-2025-64505', 4, [83194, 83232, 99170, 82700, 85509]),
    ('CVE-2025-64506', 3, [145967, 146047, 200925, 147826, 158972]),
])
def test_prebuilt_source_record_has_pinned_controls(cve, pattern_count,
                                                    offsets):
    source = ROOT / 'signatures' / cve
    pack_file = source / 'pack.json'
    pack = json.loads(pack_file.read_text(encoding='utf8'))
    assert pack['cve'] == cve and pack['schema_version'] == 3
    validate_source_pack(pack, source / 'rules-exec.yar', packfile=pack_file)
    assert len(pack['records']) == 1
    record = pack['records'][0]
    assert record['channel'] == 'production'
    assert len(record['rules']) == pattern_count
    assert record['source_type'] == 'manual'
    assert len({rule['id'] for rule in record['rules']}) == pattern_count

    manifest = json.loads(
        (RESEARCH / f'binary-first-{cve}.extended.samples.json').read_text())
    evidence = json.loads((RESEARCH / 'evidence' /
                           f'{cve}.extended.source-pack.json').read_text())
    assert manifest['cve'] == evidence['cve'] == cve
    assert evidence['status'] == 'PASS_PRELIMINARY'
    assert evidence['native_yara_x_executed'] is False
    assert evidence['production_admission'] is False
    assert evidence['counts'] == {
        'affected': 5,
        'fixed': 2,
        'backport': 1,
        'unrelated': 232
    }
    assert evidence['pattern_count'] == pattern_count
    assert len(evidence['results']) == len(manifest['samples']) == 240
    assert [item['id'] for item in manifest['samples']
           ] == [row['id'] for row in evidence['results']]
    assert [item['sha256'] for item in manifest['samples']
           ] == [row['sha256'] for row in evidence['results']]
    assert all(row['passed'] for row in evidence['results'])
    assert all(row['matched'] == (row['label'] == 'affected')
               for row in evidence['results'])
    assert [
        row['matches'][0]['file_offset']
        for row in evidence['results']
        if row['label'] == 'affected'
    ] == offsets
