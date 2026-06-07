#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <array>
#include "../core/memory.hpp"
#include "pe.hpp"

namespace revkit::analysis
{

enum class StrEncoding { ASCII, UTF16LE, Both };

struct FoundStr
{
    uintptr_t   address;
    std::string value;
    StrEncoding enc;
};

namespace detail
{

static constexpr uint8_t k_print_low  = 0x20;
static constexpr uint8_t k_print_high = 0x7E;

inline bool is_printable_byte(uint8_t b)
{
    return b >= k_print_low && b <= k_print_high;
}

inline void extract_ascii(const std::vector<uint8_t>& buf, uintptr_t base_addr,
                           size_t min_len, std::vector<FoundStr>& out)
{
    size_t run_start = 0;
    bool   in_run    = false;

    for (size_t i = 0; i <= buf.size(); ++i)
    {
        bool printable = (i < buf.size()) && is_printable_byte(buf[i]);

        if (printable)
        {
            if (!in_run)
            {
                run_start = i;
                in_run    = true;
            }
        }
        else
        {
            if (in_run)
            {
                size_t run_len = i - run_start;
                if (run_len >= min_len)
                {
                    FoundStr fs{};
                    fs.address = base_addr + run_start;
                    fs.enc     = StrEncoding::ASCII;
                    fs.value.assign(reinterpret_cast<const char*>(buf.data() + run_start), run_len);
                    out.push_back(std::move(fs));
                }
                in_run = false;
            }
        }
    }
}

inline void extract_utf16le(const std::vector<uint8_t>& buf, uintptr_t base_addr,
                             size_t min_len, std::vector<FoundStr>& out)
{
    if (buf.size() < 2)
        return;

    size_t run_start = 0;
    size_t run_chars = 0;
    bool   in_run    = false;

    size_t i = 0;
    while (i + 1 <= buf.size())
    {
        bool is_char = false;

        if (i + 1 < buf.size())
        {
            uint8_t lo = buf[i];
            uint8_t hi = buf[i + 1];
            is_char = (hi == 0) && is_printable_byte(lo);
        }

        if (is_char)
        {
            if (!in_run)
            {
                run_start = i;
                run_chars = 0;
                in_run    = true;
            }
            ++run_chars;
            i += 2;
        }
        else
        {
            if (in_run)
            {
                if (run_chars >= min_len)
                {
                    FoundStr fs{};
                    fs.address = base_addr + run_start;
                    fs.enc     = StrEncoding::UTF16LE;
                    fs.value.reserve(run_chars);
                    for (size_t c = 0; c < run_chars; ++c)
                        fs.value += static_cast<char>(buf[run_start + c * 2]);
                    out.push_back(std::move(fs));
                }
                in_run = false;
            }
            ++i;
        }
    }

    if (in_run && run_chars >= min_len)
    {
        FoundStr fs{};
        fs.address = base_addr + run_start;
        fs.enc     = StrEncoding::UTF16LE;
        fs.value.reserve(run_chars);
        for (size_t c = 0; c < run_chars; ++c)
            fs.value += static_cast<char>(buf[run_start + c * 2]);
        out.push_back(std::move(fs));
    }
}

}

inline std::vector<FoundStr> find_strings(uintptr_t addr, size_t size,
                                          StrEncoding enc, size_t min_len)
{
    std::vector<FoundStr> result;

    auto& mem = revkit::core::Memory::get();
    auto buf  = mem.read_safe(addr, size);
    if (buf.empty())
        return result;

    if (enc == StrEncoding::ASCII || enc == StrEncoding::Both)
        detail::extract_ascii(buf, addr, min_len, result);

    if (enc == StrEncoding::UTF16LE || enc == StrEncoding::Both)
        detail::extract_utf16le(buf, addr, min_len, result);

    std::sort(result.begin(), result.end(), [](const FoundStr& a, const FoundStr& b)
    {
        return a.address < b.address;
    });

    return result;
}

inline std::vector<FoundStr> find_strings_in_image(uintptr_t base, StrEncoding enc,
                                                   size_t min_len)
{
    std::vector<FoundStr> result;

    auto info = read_pe_info(base);
    if (!info)
        return result;

    static constexpr std::array<const char*, 2> k_target_sections = { ".rdata", ".data" };

    for (const char* sec_name : k_target_sections)
    {
        auto sec = find_section(base, sec_name);
        if (!sec)
            continue;

        uintptr_t sec_va   = base + sec->rva;
        size_t    sec_size = sec->vsize > 0 ? sec->vsize : sec->raw_size;

        if (sec_size == 0)
            continue;

        auto found = find_strings(sec_va, sec_size, enc, min_len);
        result.insert(result.end(), found.begin(), found.end());
    }

    std::sort(result.begin(), result.end(), [](const FoundStr& a, const FoundStr& b)
    {
        return a.address < b.address;
    });

    return result;
}

}
