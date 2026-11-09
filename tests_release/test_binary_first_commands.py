"""Exercise the documented binary-to-source commands end to end.

These fixtures check the tool contract only; they are not CVE ground truth.
"""
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools.production_db import validate_source_pack


@pytest.mark.skipif(not shutil.which('gcc') or not shutil.which('readelf'),
                    reason='requires gcc and GNU readelf')
def test_binary_samples_then_manual_pack(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    cve = 'CVE-2099-10001'
    # The test files are actual ELF64 shared libraries whose only differing
    # instruction sequence is a controlled 32-byte inline-assembly fixture.
    def module(label, payload):
        asm = tmp_path / (label + '.S')
        asm.write_text('.text\n.global fixture_' + label + '\n'
                       'fixture_' + label + ':\n'
                       + '\n'.join(f'.byte {value}' for value in payload)
                       + '\nret\n')
        path = tmp_path / (label + '.so')
        subprocess.run(['gcc', '-shared', '-fPIC', str(asm), '-o', str(path)],
                       capture_output=True, text=True, check=True)
        return path

    markers = {
        'affected': bytes(range(30, 62)),
        'fixed': bytes(range(60, 92)),
        'unrelated': bytes(range(100, 132))
    }
    paths = {name: module(name, data) for name, data in markers.items()}
    entries = [{
        'id': name,
        'label': name,
        'path': str(path),
        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'origin': 'controlled fixture',
        'label_basis': 'explicitly different assembler bytes'
    } for name, path in paths.items()]
    manifest = tmp_path / 'samples.json'
    manifest.write_text(json.dumps({
        'schema_version': 1,
        'cve': cve,
        'samples': entries
    }), encoding='utf-8')
    rule = markers['affected'].hex(' ').upper()
    report = tmp_path / 'report.json'
    screen = subprocess.run([
        sys.executable, '-m', 'tools.binary_samples', '--cve', cve,
        '--hex', rule, '--samples', str(manifest), '--output', str(report)
    ], cwd=repo, capture_output=True, text=True)
    assert screen.returncode == 0, screen.stdout + screen.stderr
    result = json.loads(report.read_text())
    assert result['status'] == 'PASS_PRELIMINARY'
    assert result['counts'] == {'affected': 1, 'fixed': 1, 'unrelated': 1,
                                'backport': 0}
    assert len(result['results'][0]['matches']) >= 1
    assert result['native_yara_x_executed'] is False

    directory = tmp_path / 'signatures' / cve
    create = subprocess.run([
        sys.executable, '-m', 'tools.manual_rules', 'init', '--cve', cve,
        '--record-key', 'variant-a', '--channel', 'test', '--hex', rule,
        '--output', str(directory)
    ], cwd=repo, capture_output=True, text=True)
    assert create.returncode == 0, create.stdout + create.stderr
    lint = subprocess.run([
        sys.executable, '-m', 'tools.manual_rules', 'lint',
        '--directory', str(directory)
    ], cwd=repo, capture_output=True, text=True)
    assert lint.returncode == 0, lint.stdout + lint.stderr
    pack = json.loads((directory / 'pack.json').read_text())
    assert pack['records'][0]['channel'] == 'test'
    validate_source_pack(pack, directory / 'rules-exec.yar',
                         packfile=directory / 'pack.json')

    # The failing fixed control must invalidate the candidate immediately.
    entries[1]['path'] = str(module('fixed_other', markers['affected'] + b'\x90'))
    entries[1]['sha256'] = hashlib.sha256(Path(entries[1]['path']).read_bytes()).hexdigest()
    manifest.write_text(json.dumps({
        'schema_version': 1,
        'cve': cve,
        'samples': entries
    }), encoding='utf-8')
    fail = subprocess.run([
        sys.executable, '-m', 'tools.binary_samples', '--cve', cve,
        '--hex', rule, '--samples', str(manifest), '--output', str(report)
    ], cwd=repo, capture_output=True, text=True)
    assert fail.returncode != 0
    assert json.loads(report.read_text())['status'] == 'FAIL_PRELIMINARY'
