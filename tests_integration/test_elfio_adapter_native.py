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
