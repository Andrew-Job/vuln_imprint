"""First-party ELF and mask semantics, exercised on actual compiler output.

These are NOT tests of Capstone or pyelftools internals: they check that the
VulnImprint adapter correctly maps code ranges, symbol scopes and mask bytes.
"""
from pathlib import Path
import subprocess

import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from factory.disasm import disassemble, mask_instruction
from factory.elf import ELF, UnsupportedBinary


def instruction(encoded: bytes):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    return next(decoder.disasm(encoded, 0x2000))


def test_rip_displacement_does_not_mask_trailing_immediate():
    # mov dword ptr [rip+0x12345678], 0x11223344
    raw = bytes.fromhex('C7 05 78 56 34 12 44 33 22 11')
    pattern = mask_instruction(instruction(raw), [])
    assert pattern is not None
    assert pattern.mask == bytes.fromhex('FF FF 00 00 00 00 FF FF FF FF')
    # Replacing the immediate changes semantics and must no longer match.
    assert not pattern.matches_at(raw[:-1] + b'\xff', 0)


def test_branch_and_arithmetic_immediates_are_distinguished():
    call = mask_instruction(instruction(bytes.fromhex('E8 01 02 03 04')), [])
    integer = mask_instruction(instruction(bytes.fromhex('05 01 02 03 04')), [])
    assert call.mask == bytes.fromhex('FF 00 00 00 00')
    assert integer.mask == b'\xff' * 5


def test_unknown_relocations_and_out_of_instruction_fields_fail_closed():
    inst = instruction(bytes.fromhex('E8 00 00 00 00'))
    assert mask_instruction(inst, [(0x2001, None)]) is None
    assert mask_instruction(inst, [(0x2004, 8)]) is None


def test_real_elf_functions_and_relocation_masking(tmp_path):
    source = tmp_path / 'component.c'
    source.write_text('''
extern int helper(int);
__attribute__((noinline)) int feature(int n){ return helper(n + 17); }
__attribute__((noinline)) int other(int n){ return n * 5; }
''')
    obj = tmp_path / 'component.o'
    subprocess.run(
        ['gcc', '-O2', '-fno-pie', '-c',
         str(source), '-o',
         str(obj)],
        check=True,
        capture_output=True)
    elf = ELF(obj)
    assert elf.kind == 1 and elf.machine == 62
    assert elf.executable_ranges()
    assert any(name == '.text' for name, _, _ in elf.symbol_ranges(['feature']))
    relocs = elf.relocations()
    assert relocs.get(
        '.text'), 'actual GCC external call relocation must be present'
    only_feature = disassemble(obj, symbols=['feature'])
    assert only_feature and all(ins.section == '.text' for ins in only_feature)
    assert any(0 in ins.normalized.mask for ins in only_feature)
    assert not disassemble(obj, symbols=['does_not_exist'])
    all_insns = disassemble(obj)
    assert len(all_insns) > len(only_feature)


def test_invalid_elf_is_never_decoded_as_code(tmp_path):
    path = tmp_path / 'broken.elf'
    path.write_bytes(b'\x7fELF' + b'\x00' * 128)
    with pytest.raises(UnsupportedBinary):
        ELF(path)
