#pragma once

#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace revkit::util
{

static constexpr char k_hex_upper[] = "0123456789ABCDEF";
static constexpr char k_base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static constexpr size_t k_addr_width = 16;
static constexpr size_t k_byte_bits  = 8;
static constexpr size_t k_b64_group  = 3;
static constexpr size_t k_b64_out    = 4;
static constexpr uint8_t k_b64_mask6 = 0x3F;
static constexpr uint8_t k_b64_mask4 = 0x0F;
static constexpr uint8_t k_b64_mask2 = 0x03;

inline std::string to_hex(const void* data, size_t size, bool spaced = true)
{
    const auto* bytes = static_cast<const uint8_t*>(data);
    std::string out;
    out.reserve(size * (spaced ? 3 : 2));
    for (size_t i = 0; i < size; ++i)
    {
        if (spaced && i > 0)
            out += ' ';
        out += k_hex_upper[(bytes[i] >> 4) & 0xF];
        out += k_hex_upper[bytes[i] & 0xF];
    }
    return out;
}

inline std::string hex_dump(const void* data, size_t size,
                            uintptr_t base_addr = 0, size_t cols = 16)
{
    const auto* bytes = static_cast<const uint8_t*>(data);
    std::ostringstream ss;
    for (size_t offset = 0; offset < size; offset += cols)
    {
        ss << std::hex << std::uppercase
           << std::setw(k_addr_width) << std::setfill('0')
           << (base_addr + offset) << "  ";
        size_t row_len = std::min(cols, size - offset);
        for (size_t c = 0; c < cols; ++c)
        {
            if (c < row_len)
            {
                ss << std::setw(2) << std::setfill('0')
                   << static_cast<unsigned>(bytes[offset + c]) << ' ';
            }
            else
            {
                ss << "   ";
            }
            if (c == cols / 2 - 1)
                ss << ' ';
        }
        ss << " |";
        for (size_t c = 0; c < row_len; ++c)
        {
            uint8_t b = bytes[offset + c];
            ss << (char)((b >= 0x20 && b < 0x7F) ? b : '.');
        }
        ss << "|\n";
    }
    return ss.str();
}

inline std::string addr_str(uintptr_t addr)
{
    std::ostringstream ss;
    ss << "0x"
       << std::hex << std::uppercase
       << std::setw(k_addr_width) << std::setfill('0')
       << addr;
    return ss.str();
}

inline uintptr_t parse_addr(const std::string& s)
{
    return static_cast<uintptr_t>(std::stoull(s, nullptr, 0));
}

inline std::string to_base64(const uint8_t* data, size_t size)
{
    std::string out;
    out.reserve(((size + k_b64_group - 1) / k_b64_group) * k_b64_out);
    size_t i = 0;
    while (i + k_b64_group <= size)
    {
        uint32_t val = (static_cast<uint32_t>(data[i]) << 16)
                     | (static_cast<uint32_t>(data[i + 1]) << 8)
                     |  static_cast<uint32_t>(data[i + 2]);
        out += k_base64_table[(val >> 18) & k_b64_mask6];
        out += k_base64_table[(val >> 12) & k_b64_mask6];
        out += k_base64_table[(val >>  6) & k_b64_mask6];
        out += k_base64_table[ val        & k_b64_mask6];
        i += k_b64_group;
    }
    size_t rem = size - i;
    if (rem == 1)
    {
        uint32_t val = static_cast<uint32_t>(data[i]) << 16;
        out += k_base64_table[(val >> 18) & k_b64_mask6];
        out += k_base64_table[(val >> 12) & k_b64_mask6];
        out += '=';
        out += '=';
    }
    else if (rem == 2)
    {
        uint32_t val = (static_cast<uint32_t>(data[i]) << 16)
                     | (static_cast<uint32_t>(data[i + 1]) << 8);
        out += k_base64_table[(val >> 18) & k_b64_mask6];
        out += k_base64_table[(val >> 12) & k_b64_mask6];
        out += k_base64_table[(val >>  6) & k_b64_mask6];
        out += '=';
    }
    return out;
}

}
