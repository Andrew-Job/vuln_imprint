"""Real ELF executable-segment matching and fail-closed sample screening."""
import hashlib
import json
import subprocess

import pytest

from factory.patterns import Pattern
from tools.binary_samples import SampleError, _executable_regions, evaluate


def test_executable_regions_reject_non_elf_and_include_real_text(tmp_path):
    fake = tmp_path / 'fake.so'
    fake.write_bytes(b'not ELF')
    with pytest.raises(SampleError, match='expected little-endian'):
        _executable_regions(fake)
    src = tmp_path / 'func.c'
    src.write_text('int function(void) { return 42; }\n')
    elf = tmp_path / 'func.so'
    subprocess.run(
        ['gcc', '-shared', '-fPIC', '-o',
         str(elf), str(src)], check=True)
    assert any(buf for _, buf in _executable_regions(elf))

    # Only a data-section copy of the bytes is insufficient for a match.
    needle = bytes(range(32, 64))
    source = tmp_path / 'data.c'
    source.write_text(
        '''__attribute__((used)) const unsigned char data[] = {''' +
        ','.join(str(b) for b in needle) +
        '};\nint function(void) { return 42; }\n')
    data_elf = tmp_path / 'data.so'
    subprocess.run(
        ['gcc', '-shared', '-fPIC', '-o',
         str(data_elf),
         str(source)],
        check=True)
    assert needle in data_elf.read_bytes()
    assert not Pattern.from_hex(needle.hex(' ')).search(
        _executable_regions(data_elf))


def test_matched_and_unmatched_sha_pinned_real_elf(tmp_path):
    # Insert a 32-byte executable anchor with GAS, preserving it in .text.
    def build(name, sequence):
        asm = tmp_path / f'{name}.S'
        asm.write_text('.text\n.global test_' + name + '\ntest_' + name +
                       ':\n' + '\n'.join(f'.byte {byte}' for byte in sequence) +
                       '\nret\n')
        path = tmp_path / f'{name}.so'
        subprocess.run(
            ['gcc', '-shared', '-fPIC', '-o',
             str(path), str(asm)],
            check=True,
            capture_output=True)
        return path

    seq = bytes(range(32, 64))
    affected = build('affected', seq)
    fixed = build('fixed', bytes(range(64, 96)))
    unrelated = build('unrelated', bytes(range(100, 132)))
    rows = []
    for sid, label, path in [('affected', 'affected', affected),
                             ('fixed', 'fixed', fixed),
                             ('unrelated', 'unrelated', unrelated)]:
        rows.append({
            'id': sid,
            'label': label,
            'path': str(path),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'origin': 'test compiled fixture',
            'label_basis': 'controlled asm fixture'
        })
    manifest = tmp_path / 'samples.json'
    manifest.write_text(
        json.dumps({
            'schema_version': 1,
            'cve': 'CVE-2026-33416',
            'samples': rows
        }))
    pattern = Pattern.from_hex(seq.hex(' '))
    result = evaluate('CVE-2026-33416', manifest, [pattern], 'test')
    assert result['status'] == 'PASS_PRELIMINARY'
    assert result['results'][0]['matches'][0]['file_offset'] >= 0
    assert result['production_admission'] is False
    # A fixed build containing the same anchor must fail, even with a
    # perfectly valid digest and a different binary identity.
    false_fixed = build('false_fixed', seq + b'\x90')
    rows[1]['path'] = str(false_fixed)
    rows[1]['sha256'] = hashlib.sha256(false_fixed.read_bytes()).hexdigest()
    manifest.write_text(
        json.dumps({
            'schema_version': 1,
            'cve': 'CVE-2026-33416',
            'samples': rows
        }))
    assert evaluate('CVE-2026-33416', manifest, [pattern],
                    'test')['status'] == 'FAIL_PRELIMINARY'
    with pytest.raises(SampleError, match='SHA-256 mismatch'):
        rows[1]['sha256'] = '0' * 64
        manifest.write_text(
            json.dumps({
                'schema_version': 1,
                'cve': 'CVE-2026-33416',
                'samples': rows
            }))
        evaluate('CVE-2026-33416', manifest, [pattern], 'test')


def test_failure_on_fixed_match_and_missing_controls(tmp_path):
    seq = bytes(range(32))
    a = tmp_path / 'a'
    b = tmp_path / 'b'
    a.write_bytes(seq)
    b.write_bytes(seq + b'0')
    rows = [{
        'id': str(i),
        'label': label,
        'path': str(path),
        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'origin': 'controlled',
        'label_basis': 'test'
    } for i, (label, path) in enumerate([('affected', a), ('fixed', b)])]
    manifest = tmp_path / 'm.json'
    manifest.write_text(
        json.dumps({
            'schema_version': 1,
            'cve': 'CVE-2026-33416',
            'samples': rows
        }))
    with pytest.raises(SampleError, match='expected little-endian'):
        evaluate('CVE-2026-33416', manifest, [Pattern.from_hex(seq.hex(' '))],
                 'test')
    manifest.write_text(
        json.dumps({
            'schema_version': 1,
            'cve': 'CVE-2026-33416',
            'samples': rows[:1]
        }))
    with pytest.raises(SampleError, match='expected little-endian'):
        evaluate('CVE-2026-33416', manifest, [Pattern.from_hex(seq.hex(' '))],
                 'test')
