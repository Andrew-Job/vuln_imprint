"""Real ELF structural admission tests; require installed pyelftools and GCC.

No mocked external YARA-X and no claims about real CVE detection.
"""
from __future__ import annotations

import struct
import subprocess
from pathlib import Path

import pytest

from factory.elf import ELF, UnsupportedBinary
from tools.production_db import ReleaseRejected, verify_static_product


def _compile(tmp_path: Path, *argv: str) -> Path:
    subprocess.run(['gcc', *argv],
                   cwd=tmp_path,
                   capture_output=True,
                   check=True,
                   timeout=30)
    return tmp_path / argv[-1]


def test_only_real_static_stripped_executables_receive_structural_credit(
        tmp_path):
    (tmp_path / 'entry.S').write_text(
        '.global _start\n_start:\nmov $60, %eax\nxor %edi, %edi\nsyscall\n')
    obj = _compile(tmp_path, '-c', 'entry.S', '-o', 'module.o')
    stripped = _compile(tmp_path, '-nostdlib', '-static', '-s', '-no-pie',
                        'entry.S', '-o', 'static-host')
    (tmp_path / 'main.c').write_text('int main(void){return 0;}\n')
    dynamic = _compile(tmp_path, 'main.c', '-o', 'dynamic-host')
    verify_static_product(stripped)
    with pytest.raises(ReleaseRejected, match='static product'):
        verify_static_product(obj)
    with pytest.raises(ReleaseRejected, match='dynamic interpreter'):
        verify_static_product(dynamic)


def test_exec_section_must_match_segment_file_offset(tmp_path):
    (tmp_path / 'main.c').write_text('int main(void) { return 0; }\n')
    valid = _compile(tmp_path, 'main.c', '-o', 'valid')
    elf = ELF(valid)
    assert elf.code_regions()
    index = next(i for i, section in enumerate(elf._file.iter_sections())
                 if section.name == '.text')
    header = elf._file.header
    # Elf64_Shdr sh_offset is 24 bytes into the section header; here we
    # intentionally corrupt *only* the file mapping of an executable section.
    entry_offset = int(header['e_shoff']) + int(header['e_shentsize']) * index
    raw = bytearray(valid.read_bytes())
    position = entry_offset + 24
    struct.pack_into('<Q', raw, position,
                     struct.unpack_from('<Q', raw, position)[0] + 1)
    mutated = tmp_path / 'mutated'
    mutated.write_bytes(raw)
    with pytest.raises(UnsupportedBinary,
                       match='does not map to PT_LOAD bytes'):
        ELF(mutated)
