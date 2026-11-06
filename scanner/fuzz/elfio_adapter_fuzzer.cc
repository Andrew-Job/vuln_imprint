// Fuzz the first-party ELFIO adapter boundary, not ELFIO's internal APIs.
// CI builds this target against the pinned upstream ELFIO Git submodule.
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "vulnimprint/elf.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    if (size > 1 << 20) return 0;
    std::vector<std::uint8_t> file(data, data + size);
    try {
        for (const auto& region : vulnimprint::executable_regions(file)) {
            if (region.offset > file.size() ||
                region.length > file.size() - region.offset) {
                __builtin_trap();
            }
        }
    } catch (const std::runtime_error&) {
        // Malformed binary is an expected, explicit rejection.
    }
    return 0;
}
