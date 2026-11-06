// Copyright VulnImprint contributors. Licensed under MIT.
#ifndef VULNIMPRINT_CVE_METADATA_H_
#define VULNIMPRINT_CVE_METADATA_H_

#include <cstddef>
#include <string_view>

namespace vulnimprint {

inline bool IsRecordId(std::string_view value) {
    if (value.size() != 27 || !value.starts_with("VI_")) {
        return false;
    }
    for (std::size_t index = 3; index < value.size(); ++index) {
        const char byte = value[index];
        if (!((byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'F'))) {
            return false;
        }
    }
    return true;
}

inline bool IsCve(std::string_view value) {
    if (!value.starts_with("CVE-") || value.size() < 13 || value[8] != '-') {
        return false;
    }
    for (std::size_t index = 4; index < value.size(); ++index) {
        if (index == 8) {
            continue;
        }
        if (value[index] < '0' || value[index] > '9') {
            return false;
        }
    }
    return true;
}

}  // namespace vulnimprint
#endif  // VULNIMPRINT_CVE_METADATA_H_
