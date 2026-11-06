"""Validated ELF64/x86-64 adapter backed by pyelftools.

All offsets are checked against original file bytes before extraction.  The
Factory intentionally supports only ELF ET_REL/ET_EXEC/ET_DYN on x86-64.
This module does not implement an independent ELF parser.
"""
from __future__ import annotations

from io import BytesIO
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection


class UnsupportedBinary(ValueError):
    """Input is not a supported ELF image or contains unsafe ranges."""


# Supported x86-64 relocation widths (System V AMD64 ABI, relocation types).
# Unknown relocations are represented with width None and reject matching code.
_RELOC_WIDTH = {
    1: 8,
    2: 4,
    4: 4,
    9: 4,
    10: 4,
    11: 4,
    24: 8,
    41: 4,
    42: 4,
}


class ELF:

    def __init__(self, path: Path):
        self.path = Path(path)
        if self.path.stat().st_size > (1 << 30):
            raise UnsupportedBinary('ELF input exceeds 1 GiB limit')
        self.raw = self.path.read_bytes()
        if len(self.raw) > (1 << 30):
            raise UnsupportedBinary('ELF input exceeds 1 GiB limit')
        try:
            self._file = ELFFile(BytesIO(self.raw))
            if (self._file.elfclass != 64 or not self._file.little_endian or
                    self._file['e_machine'] != 'EM_X86_64' or
                    self._file['e_type']
                    not in ('ET_REL', 'ET_EXEC', 'ET_DYN')):
                raise UnsupportedBinary(
                    f'expected x86-64 little-endian ELF64: {path}')
            self.kind = {
                'ET_REL': 1,
                'ET_EXEC': 2,
                'ET_DYN': 3
            }[self._file['e_type']]
            if self._file.num_sections() > 100000 or self._file.num_segments(
            ) > 10000:
                raise UnsupportedBinary(
                    'ELF header table count exceeds safety limit')
            self.machine = 62
            self.sections = {}
            self.segments = []
            self._section_indexes = {}
            for index, section in enumerate(self._file.iter_sections()):
                if not section['sh_flags'] & 0x4 or section[
                        'sh_type'] == 'SHT_NOBITS':
                    continue
                address = int(section['sh_addr'])
                offset = int(section['sh_offset'])
                size = int(section['sh_size'])
                self._check_range(offset, size)
                if section.name in self.sections:
                    raise UnsupportedBinary(
                        'duplicate executable ELF section name')
                self.sections[section.name] = (address, offset, size)
                self._section_indexes[index] = section.name
            for segment in self._file.iter_segments():
                if segment['p_type'] != 'PT_LOAD' or not (
                        int(segment['p_flags']) & 1):
                    continue
                offset, size = int(segment['p_offset']), int(
                    segment['p_filesz'])
                self._check_range(offset, size)
                if size > int(segment['p_memsz']):
                    raise UnsupportedBinary(
                        'ELF executable segment filesz exceeds memsz')
                if size:
                    self.segments.append(
                        (int(segment['p_vaddr']), offset, size))
            if (self.kind == 1 and not self.sections) or (self.kind != 1 and
                                                          not self.segments):
                raise UnsupportedBinary('no executable ELF code ranges')
            self._mapped_sections = {}
            if self.kind != 1:
                for name, (address, offset, size) in self.sections.items():
                    if not size:
                        continue
                    containing = [
                        (va, file_offset, length)
                        for va, file_offset, length in self.segments
                        if va <= address and size <= length - (address - va)
                    ]
                    if not containing:
                        continue  # non-loaded debug/executable metadata
                    if not any(offset == file_offset + address - va
                               for va, file_offset, _ in containing):
                        raise UnsupportedBinary(
                            f'executable section {name} does not map to PT_LOAD bytes'
                        )
                    self._mapped_sections[name] = (address, offset, size)
        except (ELFError, EOFError, IndexError, OverflowError,
                ValueError) as exc:
            if isinstance(exc, UnsupportedBinary):
                raise
            raise UnsupportedBinary(
                f'invalid ELF layout: {self.path}: {exc}') from exc

    def _check_range(self, offset: int, length: int) -> None:
        if offset < 0 or length < 0 or offset > len(
                self.raw) or length > len(self.raw) - offset:
            raise UnsupportedBinary(f'ELF range outside file: {self.path}')

    def executable_ranges(self) -> list[tuple[int, bytes]]:
        """File-offset-based ranges used by the Factory reference matcher."""
        blocks = self.segments if self.kind != 1 else list(
            self.sections.values())
        return [(offset, self.raw[offset:offset + size])
                for _, offset, size in blocks]

    def code_regions(self) -> list[tuple[str, int, int, bytes]]:
        """(section, VA, file offset, code), suitable for machine-code decoding."""
        if self.kind == 1:
            return [(name, address, offset, self.raw[offset:offset + size])
                    for name, (address, offset, size) in self.sections.items()
                    if size]
        # Decode executable sections where available to avoid adjacent data.
        # For stripped sectionless images, segment-based decoding remains possible.
        if self.sections:
            return [(name, address, offset, self.raw[offset:offset + size])
                    for name, (address, offset,
                               size) in self._mapped_sections.items()]
        return [(f'PT_LOAD_{i}', address, offset,
                 self.raw[offset:offset + size])
                for i, (address, offset, size) in enumerate(self.segments)]

    def instruction_offset(self, address: int, section: str) -> int | None:
        if self.kind == 1:
            block = self.sections.get(section)
            if block is None:
                return None
            base, offset, size = block
            return offset + address - base if base <= address < base + size else None
        for base, offset, size in self.segments:
            if base <= address < base + size:
                return offset + address - base
        return None

    def symbol_ranges(self, names: list[str]) -> list[tuple[str, int, int]]:
        """Return bounded executable symbol ranges, never guesses from objdump text."""
        wanted = set(names)
        found = set()
        ranges = []
        for section in self._file.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol.name not in wanted or symbol['st_info'][
                        'type'] != 'STT_FUNC':
                    continue
                section_index = symbol['st_shndx']
                if not isinstance(section_index, int):
                    continue
                code_name = self._section_indexes.get(section_index)
                if code_name is None:
                    continue
                base, _, size = self.sections[code_name]
                address = int(symbol['st_value'])
                if self.kind == 1:
                    address += base
                length = int(symbol['st_size'])
                if length <= 0 or address < base or length > size - (address -
                                                                     base):
                    continue
                signature = (code_name, address, length)
                if signature not in found:
                    ranges.append(signature)
                    found.add(signature)
        return sorted(ranges)

    def relocations(self) -> dict[str, list[tuple[int, int | None]]]:
        """Relocation coordinates are target-section-relative for ET_REL."""
        result = {}
        for section in self._file.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            target = self._section_indexes.get(int(section['sh_info']))
            if self.kind == 1 and target is None:
                continue
            for relocation in section.iter_relocations():
                address = int(relocation['r_offset'])
                width = _RELOC_WIDTH.get(int(relocation['r_info_type']))
                if self.kind == 1:
                    base = self.sections[target][0]
                    result.setdefault(target, []).append(
                        (base + address, width))
                else:
                    # Dynamic relocation offsets are virtual addresses.
                    for name, (base, _, size) in self.sections.items():
                        if base <= address < base + size:
                            result.setdefault(name, []).append((address, width))
        return result
