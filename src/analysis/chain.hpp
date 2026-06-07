#pragma once

#include <cstdint>
#include <vector>
#include <optional>
#include "../core/memory.hpp"

namespace revkit::analysis
{

inline std::optional<uintptr_t> resolve_chain(uintptr_t base,
                                               const std::vector<ptrdiff_t>& offsets)
{
    if (offsets.empty())
        return std::nullopt;

    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return std::nullopt;

    uintptr_t addr = base + static_cast<uintptr_t>(offsets[0]);

    for (size_t i = 1; i < offsets.size(); ++i)
    {
        auto deref = mem.read_val<uintptr_t>(addr);
        if (!deref || *deref == 0)
            return std::nullopt;

        addr = *deref + static_cast<uintptr_t>(offsets[i]);
    }

    return addr;
}

}
