#ifndef VULNIMPRINT_SCANNER_INCLUDE_VULNIMPRINT_ELF_H_
#define VULNIMPRINT_SCANNER_INCLUDE_VULNIMPRINT_ELF_H_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace vulnimprint {

struct Segment {
    std::size_t offset;
    std::size_t length;
    // ET_REL sections have no linked virtual address. ET_EXEC/ET_DYN hold
    // ELF-defined virtual addresses, not necessarily runtime load addresses.
    std::optional<std::uint64_t> vaddr;
};

// Validate the currently supported ELF64 x86-64 input and return
// file-backed executable regions. A new architecture requires a new adapter
// and independently validated signature profile.
std::vector<Segment> executable_regions(const std::vector<std::uint8_t>& file);

}  // namespace vulnimprint

#endif  // VULNIMPRINT_SCANNER_INCLUDE_VULNIMPRINT_ELF_H_
