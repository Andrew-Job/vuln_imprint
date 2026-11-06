"""Native contract checks for VulnImprint's ELFIO adapter, not ELFIO internals.

No mocked headers, vendor source copies, or silently skipped dependencies.
The pinned Git submodule must have been recursively initialized by CI.
"""

from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_native_elfio_adapter_supported_types_and_invalid_inputs(tmp_path):
    elfio = ROOT / 'external/elfio/elfio/elfio.hpp'
    assert elfio.is_file(
    ), 'Pinned ELFIO Git submodule is required for native CI'
    compiler = shutil.which('g++') or shutil.which('clang++')
    cc = shutil.which('cc')
    assert compiler and cc, 'Native C/C++ compilers are mandatory in CI'

    source = tmp_path / 'sample.c'
    source.write_text('int vuln_probe(void) { return 42; }\n'
                      'int main(void) { return vuln_probe() - 42; }\n')
    rel = tmp_path / 'sample.o'
    exe = tmp_path / 'sample_exec'
    dso = tmp_path / 'sample.so'
    for args in ([cc, '-c', str(source), '-o',
                  str(rel)], [cc, '-no-pie',
                              str(source), '-o',
                              str(exe)],
                 [cc, '-shared', '-fPIC',
                  str(source), '-o',
                  str(dso)]):
        subprocess.run(args, check=True, timeout=45)

    harness = tmp_path / 'contract.cc'
    harness.write_text(r'''
#include "vulnimprint/elf.h"
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <vector>

std::vector<std::uint8_t> Read(const char* path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) throw std::runtime_error("sample open failed");
  return {std::istreambuf_iterator<char>(stream),
          std::istreambuf_iterator<char>()};
}

std::uint64_t Read64(const std::vector<std::uint8_t>& b, std::size_t at) {
  std::uint64_t result = 0;
  std::memcpy(&result, b.data() + at, sizeof(result));
  return result;
}

std::uint16_t Read16(const std::vector<std::uint8_t>& b, std::size_t at) {
  std::uint16_t result = 0;
  std::memcpy(&result, b.data() + at, sizeof(result));
  return result;
}

void Write64(std::vector<std::uint8_t>& b, std::size_t at, std::uint64_t value) {
  std::memcpy(b.data() + at, &value, sizeof(value));
}

bool Rejects(const std::vector<std::uint8_t>& bytes) {
  try {
    (void)vulnimprint::executable_regions(bytes);
    return false;
  } catch (const std::runtime_error&) {
    return true;
  }
}

int main(int argc, char** argv) {
  if (argc != 4) return 10;
  for (int i = 1; i != 4; ++i) {
    auto bytes = Read(argv[i]);
    auto regions = vulnimprint::executable_regions(bytes);
    if (regions.empty()) return 11;
    for (const auto& region : regions) {
      if (region.length == 0 || region.offset > bytes.size() ||
          region.length > bytes.size() - region.offset) return 12;
    }
    if (i == 1) {
      // ET_REL has no PT_LOAD but must expose executable SHF_EXECINSTR.
      if (bytes[16] != 1 || bytes[17] != 0) return 13;
      for (const auto& region : regions) {
        if (region.offset == 0) return 14;
      }
      auto broken_sections = bytes;
      for (int j = 40; j != 48; ++j) broken_sections[j] = 0xff;
      if (!Rejects(broken_sections)) return 15;
      auto wrong_section_size = bytes;
      wrong_section_size[58] = 1;
      wrong_section_size[59] = 0;
      if (!Rejects(wrong_section_size)) return 21;
      auto too_many_sections = bytes;
      too_many_sections[60] = 0xff;
      too_many_sections[61] = 0x7f;
      if (!Rejects(too_many_sections)) return 22;
      // A nonexecutable section cannot point beyond the file, even when the
      // executable section itself is valid.
      const auto shoff = Read64(bytes, 40);
      const auto shentsize = Read16(bytes, 58);
      const auto shnum = Read16(bytes, 60);
      bool mutated_nonexec = false;
      for (int j = 0; j < shnum; ++j) {
        const auto pos = shoff + static_cast<std::size_t>(j) * shentsize;
        const auto type = bytes[pos];
        const auto flags = Read64(bytes, pos + 8);
        const auto size = Read64(bytes, pos + 32);
        if (type == 1 && (flags & 4) == 0 && size != 0) {
          auto bad_range = bytes;
          Write64(bad_range, pos + 24, bytes.size() + 1);
          if (!Rejects(bad_range)) return 23;
          mutated_nonexec = true;
          break;
        }
      }
      if (!mutated_nonexec) return 24;
      // SHT_NULL must not be selected even if malicious flags claim it is
      // executable and its file span is outside the input buffer.
      auto poisoned_null = bytes;
      Write64(poisoned_null, shoff + 8, 4);  // SHF_EXECINSTR
      Write64(poisoned_null, shoff + 24, bytes.size() + 4096);
      Write64(poisoned_null, shoff + 32, 16);
      const auto safe_regions = vulnimprint::executable_regions(poisoned_null);
      if (safe_regions.empty()) return 27;
      for (const auto& region : safe_regions) {
        if (region.offset > bytes.size() ||
            region.length > bytes.size() - region.offset) return 28;
      }
    }
    if (i == 2) {
      auto broken_segments = bytes;
      for (int j = 32; j != 40; ++j) broken_segments[j] = 0xff;
      if (!Rejects(broken_segments)) return 16;
      const auto phoff = Read64(bytes, 32);
      const auto phentsize = Read16(bytes, 54);
      const auto phnum = Read16(bytes, 56);
      bool mutated_load = false;
      for (int j = 0; j < phnum; ++j) {
        const auto pos = phoff + static_cast<std::size_t>(j) * phentsize;
        if (bytes[pos] == 1 && (bytes[pos + 4] & 1) != 0) {
          auto bad_memsz = bytes;
          Write64(bad_memsz, pos + 40, 0);
          if (!Rejects(bad_memsz)) return 25;
          mutated_load = true;
          break;
        }
      }
      if (!mutated_load) return 26;
    }
    auto wrong_arch = bytes;
    wrong_arch[18] = 3;  // EM_386, not EM_X86_64
    wrong_arch[19] = 0;
    if (!Rejects(wrong_arch)) return 17;
    auto wrong_class = bytes;
    wrong_class[4] = 1;  // ELFCLASS32 is unsupported
    if (!Rejects(wrong_class)) return 18;
    if (!Rejects(std::vector<std::uint8_t>{1,2,3,4})) return 19;
    auto core = bytes;
    core[16] = 4; core[17] = 0;  // ET_CORE is deliberately unsupported
    if (!Rejects(core)) return 20;
  }
  return 0;
}
''')
    binary = tmp_path / 'contract'
    subprocess.run(
        [
            compiler, '-std=c++20', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
            '-I',
            str(ROOT / 'scanner/include'), '-I',
            str(ROOT / 'external/elfio'),
            str(ROOT / 'scanner/src/elf.cc'),
            str(harness), '-o',
            str(binary)
        ],
        check=True,
        timeout=90,
    )
    subprocess.run([str(binary), str(rel),
                    str(exe), str(dso)],
                   check=True,
                   timeout=30)


def test_rx_segment_does_not_expose_nonexecuting_rodata(tmp_path):
    """Own range-selection policy: PF_X PT_LOAD may contain .rodata."""
    elfio = ROOT / 'external/elfio/elfio/elfio.hpp'
    assert elfio.is_file(), 'Pinned ELFIO dependency required in native CI'
    cc = shutil.which('cc')
    cxx = shutil.which('g++') or shutil.which('clang++')
    assert cc and cxx
    source = tmp_path / 'mixed.c'
    source.write_text(
        """__attribute__((used)) const char sentinel[] = "VULNIMPRINT_INERT_BYTES";
int main(void) { return sentinel[0] == 0; }
""")
    binary = tmp_path / 'mixed'
    subprocess.run(
        [cc, '-Wl,-z,noseparate-code',
         str(source), '-o',
         str(binary)],
        check=True,
        timeout=45)
    harness = tmp_path / 'ranges.cc'
    harness.write_text(r'''#include "vulnimprint/elf.h"
#include <cstdint>
#include <fstream>
#include <iterator>
#include <vector>
#include <cstring>
#include <algorithm>
int main(int argc, char** argv) {
  if (argc != 2) return 10;
  std::ifstream stream(argv[1], std::ios::binary);
  std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(stream),
                                   std::istreambuf_iterator<char>()};
  const char needle[] = "VULNIMPRINT_INERT_BYTES";
  if (std::search(bytes.begin(), bytes.end(), needle, needle + sizeof(needle) - 1)
      == bytes.end()) return 11;
  for (const auto& region : vulnimprint::executable_regions(bytes)) {
    for (std::size_t pos = region.offset; pos + sizeof(needle) - 1 <= region.offset + region.length; ++pos) {
      if (std::memcmp(bytes.data() + pos, needle, sizeof(needle) - 1) == 0) return 12;
    }
  }
  return 0;
}''')
    output = tmp_path / 'ranges'
    subprocess.run([
        cxx, '-std=c++20', '-I',
        str(ROOT / 'scanner/include'), '-I',
        str(ROOT / 'external/elfio'),
        str(harness),
        str(ROOT / 'scanner/src/elf.cc'), '-o',
        str(output)
    ],
                   check=True,
                   timeout=90)
    subprocess.run([str(output), str(binary)], check=True, timeout=45)


def test_executable_section_load_intersection_preserves_offsets(tmp_path):
    """An RX PT_LOAD ending inside .text must expose only backed .text bytes."""
    import struct

    from factory.elf import ELF

    root = ROOT
    assert (root / 'external/elfio/elfio/elfio.hpp').is_file()
    cc = shutil.which('cc')
    cxx = shutil.which('g++') or shutil.which('clang++')
    assert cc and cxx
    source = tmp_path / 'intersection.c'
    source.write_text('int main(void) { return 17; }\n')
    original = tmp_path / 'original'
    subprocess.run([cc, '-O2', '-no-pie',
                    str(source), '-o',
                    str(original)],
                   check=True,
                   timeout=30)
    parsed = ELF(original)
    section = next(s for s in parsed._file.iter_sections() if s.name == '.text')
    text_offset = int(section['sh_offset'])
    text_va = int(section['sh_addr'])
    text_size = int(section['sh_size'])
    assert text_size > 16
    half = text_size // 2
    header = parsed._file.header
    patched = bytearray(original.read_bytes())
    modified_segment = False
    for index, segment in enumerate(parsed._file.iter_segments()):
        if segment['p_type'] != 'PT_LOAD' or not int(segment['p_flags']) & 1:
            continue
        segment_offset = int(segment['p_offset'])
        segment_va = int(segment['p_vaddr'])
        if (segment_offset <= text_offset and text_offset + text_size
                <= segment_offset + int(segment['p_filesz']) and
                segment_va + text_offset - segment_offset == text_va):
            file_size = text_offset - segment_offset + half
            phdr = int(header['e_phoff']) + index * int(header['e_phentsize'])
            struct.pack_into('<Q', patched, phdr + 32, file_size)
            modified_segment = True
            break
    assert modified_segment, 'fixture requires a file-backed .text PT_LOAD'
    shortened = tmp_path / 'clipped'
    shortened.write_bytes(patched)

    # The Factory reference scanner and its disassembler must agree on the
    # reduced original-file span, not silently drop the partially backed code.
    factory_regions = ELF(shortened).code_regions()
    text_regions = [(addr, offset, len(buf))
                    for name, addr, offset, buf in factory_regions
                    if name == '.text']
    assert text_regions == [(text_va, text_offset, half)]

    harness = tmp_path / 'intersection.cc'
    harness.write_text(r'''
#include "vulnimprint/elf.h"
#include <cstdint>
#include <fstream>
#include <iterator>
#include <vector>
#include <cstdlib>
int main(int argc, char** argv) {
  if (argc != 5) return 10;
  std::ifstream stream(argv[1], std::ios::binary);
  std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(stream),
                                   std::istreambuf_iterator<char>()};
  const auto offset = static_cast<std::size_t>(std::strtoull(argv[2], nullptr, 10));
  const auto length = static_cast<std::size_t>(std::strtoull(argv[3], nullptr, 10));
  const auto va = static_cast<std::uint64_t>(std::strtoull(argv[4], nullptr, 10));
  bool found = false;
  for (const auto& r : vulnimprint::executable_regions(bytes)) {
    if (r.offset == offset && r.length == length && r.vaddr == va) found = true;
    if (r.offset > bytes.size() || r.length > bytes.size() - r.offset) return 11;
  }
  return found ? 0 : 12;
}
''')
    compiled = tmp_path / 'intersection'
    subprocess.run([
        cxx, '-std=c++20', '-Wall', '-Wextra', '-Wpedantic', '-Werror', '-I',
        str(root / 'scanner/include'), '-I',
        str(root / 'external/elfio'),
        str(root / 'scanner/src/elf.cc'),
        str(harness), '-o',
        str(compiled)
    ],
                   check=True,
                   timeout=90)
    subprocess.run([
        str(compiled),
        str(shortened),
        str(text_offset),
        str(half),
        str(text_va)
    ],
                   check=True,
                   timeout=30)
