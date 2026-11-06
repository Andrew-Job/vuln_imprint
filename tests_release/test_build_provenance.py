"""First-party compiler/build evidence: real GCC objects and tamper rejection."""
import json
import subprocess
from pathlib import Path

import pytest

from factory.build_provenance import verify_record, write_record
from factory.toolchains import ToolchainMismatch, probe_compiler


def _run(*args, cwd):
    subprocess.run([str(arg) for arg in args],
                   cwd=cwd,
                   check=True,
                   capture_output=True,
                   timeout=30)


def test_actual_compiler_source_and_binary_artifacts_are_bound(tmp_path):
    (tmp_path / 'source-provenance.json').write_text(
        json.dumps({
            'type': 'git',
            'commit': 'a' * 40,
            'url': 'https://example.org/library.git',
        }))
    (tmp_path / 'module.c').write_text('int component(void){return 73;}\n')
    (tmp_path / 'main.c').write_text(
        'int component(void);int main(void){return component()!=73;}\n')
    compiler = probe_compiler('gcc', optimization='-O2')
    _run('gcc', '-O2', '-c', 'module.c', '-o', 'module.o', cwd=tmp_path)
    _run('ar', 'rcs', 'libcomponent.a', 'module.o', cwd=tmp_path)
    for host in ('host_0', 'host_1'):
        _run('gcc', '-O2', 'main.c', 'module.o', '-o', host, cwd=tmp_path)
    commands = [['gcc', '-O2', '-c', 'module.c', '-o', 'module.o']]
    record = write_record(tmp_path, compiler, commands)
    assert verify_record(tmp_path, record['source'], compiler) == record
    assert record['artifacts']['module.o']

    (tmp_path / 'module.o').write_bytes(b'tampered')
    with pytest.raises(ToolchainMismatch, match='build artifact changed'):
        verify_record(tmp_path, record['source'], compiler)


def test_source_provenance_change_is_detected(tmp_path):
    (tmp_path / 'source-provenance.json').write_text(
        json.dumps({
            'type': 'git',
            'commit': 'a' * 40,
        }))
    for name in ('module.o', 'libcomponent.a', 'host_0', 'host_1'):
        (tmp_path / name).write_bytes(f'test:{name}'.encode())
    compiler = probe_compiler('gcc', optimization='-O2')
    record = write_record(tmp_path, compiler, [['gcc', '-O2', 'module.c']])
    (tmp_path / 'source-provenance.json').write_text(
        json.dumps({
            'type': 'git',
            'commit': 'b' * 40,
        }))
    with pytest.raises(ToolchainMismatch, match='source or toolchain'):
        verify_record(tmp_path, record['source'], compiler)
