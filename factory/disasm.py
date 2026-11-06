"""Instruction-aligned x86-64 mining with Capstone decoder detail.

Never derive displacement or immediate byte positions from printed assembly.
Unknown relocations and invalid instruction encodings are excluded from masks.
"""
from __future__ import annotations

from dataclasses import dataclass
from bisect import bisect_left
from pathlib import Path

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from .elf import ELF, UnsupportedBinary
from .patterns import Pattern


@dataclass(frozen=True)
class Instruction:
    section: str
    va: int
    file_offset: int
    raw: bytes
    normalized: Pattern
    text: str


def _clear_field(mask: bytearray, offset: int, size: int) -> bool:
    if not isinstance(offset, int) or not isinstance(size, int):
        return False
    if offset < 0 or size <= 0 or offset + size > len(mask):
        return False
    mask[offset:offset + size] = b'\x00' * size
    return True


def mask_instruction(insn, relocations: list[tuple[int, int | None]]) -> Pattern | None:
    """Mask precisely encoded relocations and address-dependent operands."""
    raw = bytes(insn.bytes)
    if not raw or len(raw) > 15:
        return None
    mask = bytearray(b'\xff' * len(raw))
    start, end = int(insn.address), int(insn.address) + len(raw)
    for at, size in relocations:
        if start <= at < end:
            if size is None or at + size > end:
                return None
            if not _clear_field(mask, at - start, size):
                return None
        elif at < start and size is not None and at + size > start:
            return None
        elif at < start and size is None and start - at <= 15:
            # Unknown relocation width: conservatively exclude nearby code.
            return None
    if any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP
           for op in insn.operands):
        if not _clear_field(mask, insn.disp_offset, insn.disp_size):
            return None
    if (insn.group(CS_GRP_CALL) or insn.group(CS_GRP_JUMP)) and any(
            op.type == X86_OP_IMM for op in insn.operands):
        if not _clear_field(mask, insn.imm_offset, insn.imm_size):
            return None
    return Pattern(raw, bytes(mask))


def disassemble(path: Path, symbols: list[str] | None = None,
                max_instructions: int = 150000) -> list[Instruction]:
    if max_instructions < 1:
        raise ValueError('max_instructions must be positive')
    elf = ELF(path)
    if elf.kind != 1 and not elf.sections:
        # Native Scanner may safely scan a stripped, sectionless ET_EXEC/DYN,
        # but Factory cannot safely mine relocation-aware masks from one.
        raise UnsupportedBinary('sectionless linked ELF is not a safe mining input')
    relocs = elf.relocations()
    scopes = elf.symbol_ranges(symbols) if symbols else None
    if scopes is not None and not scopes:
        return []  # never silently fall back to unscoped mining
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    decoder.skipdata = False
    output = []
    seen = set()
    for name, va, offset, data in elf.code_regions():
        # Index relocation offsets once; passing the entire section's relocation
        # table to every instruction has quadratic cost on large object files.
        entries = sorted(relocs.get(name, []), key=lambda item: item[0])
        positions = [item[0] for item in entries]
        ranges = [(va, len(data))] if scopes is None else [
            (start, size) for sec, start, size in scopes if sec == name]
        for start, size in ranges:
            relative = start - va
            if relative < 0 or size < 1 or relative + size > len(data):
                continue
            block = data[relative:relative + size]
            cursor = 0
            while cursor < len(block):
                # Decode contiguous instructions in one Capstone call instead of
                # repeatedly copying the remaining suffix (quadratic overhead).
                before = cursor
                for decoded in decoder.disasm(block[cursor:], start + cursor):
                    insn_offset = offset + relative + decoded.address - start
                    key = (name, decoded.address)
                    lo = bisect_left(positions, int(decoded.address) - 15)
                    hi = bisect_left(positions, int(decoded.address) + decoded.size)
                    normalized = mask_instruction(decoded, entries[lo:hi])
                    if normalized is not None and key not in seen:
                        output.append(Instruction(name, decoded.address, insn_offset,
                                                  bytes(decoded.bytes), normalized,
                                                  f'{decoded.mnemonic} {decoded.op_str}'.strip()))
                        seen.add(key)
                        if len(output) >= max_instructions:
                            return sorted(output, key=lambda ins: ins.file_offset)
                    cursor = int(decoded.address) + decoded.size - start
                # Capstone stops on invalid data; resume *after* the invalid
                # byte. A gap breaks instruction-aligned pattern windows.
                if cursor == before or cursor < len(block):
                    cursor += 1
    return sorted(output, key=lambda ins: ins.file_offset)
