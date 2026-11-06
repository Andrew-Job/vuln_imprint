#ifndef VULNIMPRINT_SCANNER_INCLUDE_VULNIMPRINT_JSON_H_
#define VULNIMPRINT_SCANNER_INCLUDE_VULNIMPRINT_JSON_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace vulnimprint {
namespace internal {

inline constexpr char kHexDigits[] = "0123456789abcdef";

inline void AppendUnicodeEscape(std::string& output, unsigned char byte) {
    output += "\\u00";
    output += kHexDigits[byte >> 4];
    output += kHexDigits[byte & 0x0f];
}

// Return the number of bytes in a valid UTF-8 sequence starting at offset,
// or zero when the input does not encode a Unicode scalar value.
inline std::size_t ValidUtf8Width(std::string_view input, std::size_t offset) {
    const auto first = static_cast<unsigned char>(input[offset]);
    std::size_t width = 0;
    std::uint32_t codepoint = 0;
    std::uint32_t minimum = 0;
    if (first >= 0xc2 && first <= 0xdf) {
        width = 2;
        codepoint = first & 0x1f;
        minimum = 0x80;
    } else if (first >= 0xe0 && first <= 0xef) {
        width = 3;
        codepoint = first & 0x0f;
        minimum = 0x800;
    } else if (first >= 0xf0 && first <= 0xf4) {
        width = 4;
        codepoint = first & 0x07;
        minimum = 0x10000;
    } else {
        return 0;
    }
    if (width > input.size() - offset) return 0;
    for (std::size_t index = 1; index < width; ++index) {
        const auto byte = static_cast<unsigned char>(input[offset + index]);
        if ((byte & 0xc0) != 0x80) return 0;
        codepoint = (codepoint << 6) | (byte & 0x3f);
    }
    if (codepoint < minimum || codepoint > 0x10ffff ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
        return 0;
    }
    return width;
}

}  // namespace internal

// Always emits valid JSON containing valid UTF-8. Invalid input bytes become
// U+FFFD; use HexBytes(path.native()) to preserve a Linux pathname exactly.
inline std::string JsonString(std::string_view input) {
    std::string result;
    result.reserve(input.size() + 2);
    result.push_back('"');
    for (std::size_t offset = 0; offset < input.size();) {
        const auto byte = static_cast<unsigned char>(input[offset]);
        if (byte < 0x80) {
            switch (byte) {
                case '"':
                    result += "\\\"";
                    break;
                case '\\':
                    result += "\\\\";
                    break;
                case '\b':
                    result += "\\b";
                    break;
                case '\f':
                    result += "\\f";
                    break;
                case '\n':
                    result += "\\n";
                    break;
                case '\r':
                    result += "\\r";
                    break;
                case '\t':
                    result += "\\t";
                    break;
                default:
                    if (byte < 0x20) {
                        internal::AppendUnicodeEscape(result, byte);
                    } else {
                        result.push_back(static_cast<char>(byte));
                    }
            }
            ++offset;
            continue;
        }
        const std::size_t width = internal::ValidUtf8Width(input, offset);
        if (width == 0) {
            result += "\\ufffd";
            ++offset;
        } else {
            result.append(input.substr(offset, width));
            offset += width;
        }
    }
    result.push_back('"');
    return result;
}

// Byte-for-byte filename recovery independent of locale and Unicode rules.
inline std::string HexBytes(std::string_view bytes) {
    std::string result;
    result.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) {
        result.push_back(internal::kHexDigits[byte >> 4]);
        result.push_back(internal::kHexDigits[byte & 0x0f]);
    }
    return result;
}

}  // namespace vulnimprint

#endif  // VULNIMPRINT_SCANNER_INCLUDE_VULNIMPRINT_JSON_H_
