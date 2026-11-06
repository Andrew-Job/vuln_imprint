#ifndef VULNIMPRINT_SCANNER_INCLUDE_VULNIMPRINT_MATCH_LOCATION_H_
#define VULNIMPRINT_SCANNER_INCLUDE_VULNIMPRINT_MATCH_LOCATION_H_

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>

#include "vulnimprint/elf.h"

namespace vulnimprint {

struct MatchLocation {
    bool executable = false;
    std::optional<std::uint64_t> virtual_address;
};

// The match offset is always a file offset. Require the whole match to fit
// inside one executable file-backed region; an overlap is not sufficient.
// ET_REL has no linked VA. Ambiguous overlapping mappings have no single VA.
inline MatchLocation LocateMatch(std::span<const Segment> regions,
                                 std::size_t offset, std::size_t length) {
    MatchLocation result;
    bool ambiguous_address = false;
    if (length == 0) return result;

    for (const auto& region : regions) {
        if (offset < region.offset) continue;
        const auto relative = offset - region.offset;
        if (relative >= region.length || length > region.length - relative) {
            continue;
        }
        result.executable = true;
        if (!region.vaddr) {
            ambiguous_address = true;
            continue;
        }
        const auto max_address = std::numeric_limits<std::uint64_t>::max();
        if (relative > max_address - *region.vaddr) {
            throw std::overflow_error("ELF virtual address overflow");
        }
        const auto address = *region.vaddr + relative;
        if (result.virtual_address && *result.virtual_address != address) {
            ambiguous_address = true;
        }
        result.virtual_address = address;
    }
    if (ambiguous_address) result.virtual_address.reset();
    return result;
}

}  // namespace vulnimprint

#endif  // VULNIMPRINT_SCANNER_INCLUDE_VULNIMPRINT_MATCH_LOCATION_H_
