// ELFIO decodes ELF structures; VulnImprint validates trust boundaries and
// selects only file-backed executable regions for its scanning contract.
#include "vulnimprint/elf.h"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elfio/elfio.hpp>
#include <ios>
#include <istream>
#include <limits>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <vector>

namespace vulnimprint {
namespace {

static_assert(std::endian::native == std::endian::little);
using ELFIO::Elf64_Ehdr;
using ELFIO::Elf64_Phdr;
using ELFIO::Elf64_Shdr;
static_assert(sizeof(Elf64_Ehdr) == 64);
static_assert(sizeof(Elf64_Phdr) == 56);
static_assert(sizeof(Elf64_Shdr) == 64);
constexpr std::uint16_t kExtendedCount = 0xffff;
constexpr std::uint16_t kUndefinedSection = 0;
constexpr std::size_t kClassIndex = 4;
constexpr std::size_t kDataIndex = 5;
constexpr std::size_t kVersionIndex = 6;

// ELFIO requires a seekable istream. C++20 does not have std::ispanstream,
// so provide a read-only view of the already validated input buffer.
// No second full-size string or stream buffer is allocated.
class MemoryStreamBuf final : public std::streambuf {
   public:
    explicit MemoryStreamBuf(const std::vector<std::uint8_t>& bytes) {
        auto* begin = reinterpret_cast<char*>(
                const_cast<std::uint8_t*>(bytes.data()));
        setg(begin, begin, begin + bytes.size());
    }

   protected:
    pos_type seekoff(off_type offset, std::ios_base::seekdir direction,
                     std::ios_base::openmode mode) override {
        if ((mode & std::ios_base::in) == 0) return pos_type(off_type(-1));
        const auto length = egptr() - eback();
        const auto current = gptr() - eback();
        off_type base = 0;
        switch (direction) {
            case std::ios_base::beg:
                break;
            case std::ios_base::cur:
                base = current;
                break;
            case std::ios_base::end:
                base = length;
                break;
            default:
                return pos_type(off_type(-1));
        }
        // Compare before adding to avoid signed integer overflow.
        if (offset < -base || offset > length - base) {
            return pos_type(off_type(-1));
        }
        const auto next = base + offset;
        setg(eback(), eback() + next, egptr());
        return pos_type(next);
    }

    pos_type seekpos(pos_type position, std::ios_base::openmode mode) override {
        return seekoff(static_cast<off_type>(position), std::ios_base::beg,
                       mode);
    }
};

struct HeaderCounts {
    std::uint64_t sections;
    std::uint64_t segments;
};

void VerifyFileSpan(std::size_t file_size, std::uint64_t offset,
                    std::uint64_t length) {
    if (offset > file_size || length > file_size - offset) {
        throw std::runtime_error("ELF region extends beyond the file");
    }
}

void VerifyTable(std::size_t file_size, std::uint64_t offset,
                 std::uint64_t count, std::uint64_t item_size) {
    if (count == 0) return;
    if (item_size == 0 || offset > file_size ||
        count > (file_size - offset) / item_size) {
        throw std::runtime_error("Truncated or oversized ELF header table");
    }
}

// Preflight *only* the two header tables before passing untrusted bytes into
// ELFIO. ELFIO 3.12's load() does not propagate every load_sections() failure.
// This is a bounds check, not a second ELF parser or a disassembler.
HeaderCounts PreflightTables(const std::vector<std::uint8_t>& file) {
    if (file.size() < sizeof(Elf64_Ehdr) || file.size() > (1ULL << 30)) {
        throw std::runtime_error("Truncated or oversized ELF file");
    }
    Elf64_Ehdr header{};
    std::memcpy(&header, file.data(), sizeof(header));
    if (std::memcmp(header.e_ident,
                    "\x7f"
                    "ELF",
                    4) != 0 ||
        header.e_ident[kClassIndex] != ELFIO::ELFCLASS64 ||
        header.e_ident[kDataIndex] != ELFIO::ELFDATA2LSB ||
        header.e_ident[kVersionIndex] != ELFIO::EV_CURRENT ||
        header.e_ehsize != sizeof(Elf64_Ehdr)) {
        throw std::runtime_error("Invalid ELF64 header");
    }
    if (header.e_shoff != 0 && header.e_shentsize != sizeof(Elf64_Shdr)) {
        throw std::runtime_error("Invalid ELF section-header size");
    }
    if (header.e_shoff == 0 && header.e_shnum != 0) {
        throw std::runtime_error("Missing ELF section-header table");
    }
    if (header.e_phnum != 0 &&
        (header.e_phoff == 0 || header.e_phentsize != sizeof(Elf64_Phdr))) {
        throw std::runtime_error("Invalid ELF program-header table");
    }

    std::uint64_t sections = header.e_shnum;
    std::uint64_t segments = header.e_phnum;
    const bool needs_section_zero = (header.e_shoff != 0 && sections == 0) ||
                                    header.e_phnum == kExtendedCount ||
                                    header.e_shstrndx == kExtendedCount;
    Elf64_Shdr section_zero{};
    if (needs_section_zero) {
        if (header.e_shoff == 0 || header.e_shentsize != sizeof(Elf64_Shdr)) {
            throw std::runtime_error("Missing ELF extended-numbering section");
        }
        VerifyTable(file.size(), header.e_shoff, 1, sizeof(Elf64_Shdr));
        std::memcpy(&section_zero, file.data() + header.e_shoff,
                    sizeof(section_zero));
    }
    if (header.e_shoff != 0 && sections == 0) sections = section_zero.sh_size;
    if (header.e_phnum == kExtendedCount) segments = section_zero.sh_info;
    if (sections > 100000 || segments > 10000) {
        throw std::runtime_error("ELF header count exceeds safety limit");
    }
    if (header.e_shoff != 0 && sections == 0) {
        throw std::runtime_error("Empty ELF section-header table");
    }
    if (header.e_shstrndx == kExtendedCount) {
        if (section_zero.sh_link >= sections) {
            throw std::runtime_error("Invalid extended section-name index");
        }
    } else if (header.e_shstrndx != kUndefinedSection &&
               header.e_shstrndx >= sections) {
        throw std::runtime_error("Invalid section-name index");
    }
    VerifyTable(file.size(), header.e_shoff, sections, sizeof(Elf64_Shdr));
    VerifyTable(file.size(), header.e_phoff, segments, sizeof(Elf64_Phdr));
    return {sections, segments};
}

}  // namespace

std::vector<Segment> executable_regions(const std::vector<std::uint8_t>& file) {
    const auto header_counts = PreflightTables(file);
    // Do not reopen the filesystem path: the scanner has already size-limited
    // and read the original regular file with O_NOFOLLOW.
    MemoryStreamBuf buffer(file);
    std::istream stream(&buffer);
    ELFIO::elfio reader;
    if (!reader.load(stream)) {
        throw std::runtime_error("Invalid ELF structure");
    }
    if (reader.sections.size() != header_counts.sections ||
        reader.segments.size() != header_counts.segments) {
        throw std::runtime_error("ELFIO did not load all declared headers");
    }
    if (reader.get_class() != ELFIO::ELFCLASS64 ||
        reader.get_encoding() != ELFIO::ELFDATA2LSB ||
        reader.get_machine() != ELFIO::EM_X86_64 ||
        reader.get_elf_version() != ELFIO::EV_CURRENT) {
        throw std::runtime_error(
                "Only little-endian ELF64 x86-64 is supported");
    }
    const auto type = reader.get_type();
    if (type != ELFIO::ET_EXEC && type != ELFIO::ET_DYN &&
        type != ELFIO::ET_REL) {
        throw std::runtime_error("Unsupported ELF type");
    }

    // Check *all* loaded section and PT_LOAD file spans, not merely selected
    // executable ones. A corrupt unrelated section must not be silently
    // ignored.
    for (const auto& section : reader.sections) {
        if (section->get_type() != ELFIO::SHT_NOBITS &&
            section->get_type() != ELFIO::SHT_NULL) {
            VerifyFileSpan(file.size(), section->get_offset(),
                           section->get_size());
        }
    }
    for (const auto& segment : reader.segments) {
        if (segment->get_type() == ELFIO::PT_LOAD) {
            if (segment->get_file_size() > segment->get_memory_size()) {
                throw std::runtime_error("ELF PT_LOAD filesz exceeds memsz");
            }
            VerifyFileSpan(file.size(), segment->get_offset(),
                           segment->get_file_size());
        }
    }

    std::vector<Segment> regions;
    if (type == ELFIO::ET_REL) {
        for (const auto& section : reader.sections) {
            if ((section->get_flags() & ELFIO::SHF_EXECINSTR) == 0 ||
                section->get_type() == ELFIO::SHT_NULL ||
                section->get_type() == ELFIO::SHT_NOBITS ||
                section->get_size() == 0) {
                continue;
            }
            regions.push_back({static_cast<std::size_t>(section->get_offset()),
                               static_cast<std::size_t>(section->get_size()),
                               std::nullopt});
        }
    } else {
        for (const auto& segment : reader.segments) {
            if (segment->get_type() != ELFIO::PT_LOAD ||
                (segment->get_flags() & ELFIO::PF_X) == 0 ||
                segment->get_file_size() == 0) {
                continue;
            }
            regions.push_back(
                    {static_cast<std::size_t>(segment->get_offset()),
                     static_cast<std::size_t>(segment->get_file_size()),
                     segment->get_virtual_address()});
        }
    }
    if (regions.empty()) {
        throw std::runtime_error("No executable ELF regions found");
    }
    return regions;
}

}  // namespace vulnimprint
