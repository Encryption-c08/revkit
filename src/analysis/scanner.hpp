#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include "../core/memory.hpp"

namespace revkit::analysis
{

struct PatternByte
{
    uint8_t value;
    bool    wildcard;
};

struct Match
{
    uintptr_t address;
};

namespace detail
{

static constexpr DWORD k_readable_protect_mask =
    PAGE_READONLY          |
    PAGE_READWRITE         |
    PAGE_WRITECOPY         |
    PAGE_EXECUTE_READ      |
    PAGE_EXECUTE_READWRITE |
    PAGE_EXECUTE_WRITECOPY;

inline bool is_region_readable(DWORD protect)
{
    if (protect & PAGE_NOACCESS) return false;
    if (protect & PAGE_GUARD)    return false;
    return (protect & k_readable_protect_mask) != 0;
}

}

inline std::vector<PatternByte> parse_pattern(const std::string& pattern)
{
    std::vector<PatternByte> result;
    std::istringstream stream(pattern);
    std::string token;

    while (stream >> token)
    {
        PatternByte pb{};
        if (token == "?" || token == "??")
        {
            pb.wildcard = true;
            pb.value    = 0;
        }
        else
        {
            pb.wildcard = false;
            pb.value    = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
        }
        result.push_back(pb);
    }

    return result;
}

inline std::vector<size_t> match_buffer(const uint8_t* data, size_t size,
                                        const std::vector<PatternByte>& pattern)
{
    std::vector<size_t> offsets;

    if (pattern.empty() || size < pattern.size())
        return offsets;

    size_t scan_end = size - pattern.size() + 1;

    for (size_t i = 0; i < scan_end; ++i)
    {
        bool matched = true;
        for (size_t j = 0; j < pattern.size(); ++j)
        {
            if (!pattern[j].wildcard && data[i + j] != pattern[j].value)
            {
                matched = false;
                break;
            }
        }
        if (matched)
            offsets.push_back(i);
    }

    return offsets;
}

inline std::vector<Match> scan_process(const std::string& ida_pattern,
                                       size_t max_results)
{
    std::vector<Match> results;

    auto parsed = parse_pattern(ida_pattern);
    if (parsed.empty())
        return results;

    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return results;

    for (const auto& region : mem.regions())
    {
        if (results.size() >= max_results)
            break;

        if (region.state != MEM_COMMIT)
            continue;

        if (!detail::is_region_readable(region.protect))
            continue;

        auto bytes = mem.read_safe(region.base, region.size);
        if (bytes.empty())
            continue;

        auto offsets = match_buffer(bytes.data(), bytes.size(), parsed);

        for (size_t off : offsets)
        {
            if (results.size() >= max_results)
                break;
            results.push_back(Match{ region.base + off });
        }
    }

    return results;
}

inline std::vector<Match> scan_range(uintptr_t start, size_t length,
                                     const std::string& ida_pattern)
{
    std::vector<Match> results;

    auto parsed = parse_pattern(ida_pattern);
    if (parsed.empty())
        return results;

    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return results;

    auto bytes = mem.read_safe(start, length);
    if (bytes.empty())
        return results;

    auto offsets = match_buffer(bytes.data(), bytes.size(), parsed);

    results.reserve(offsets.size());
    for (size_t off : offsets)
        results.push_back(Match{ start + off });

    return results;
}

}
