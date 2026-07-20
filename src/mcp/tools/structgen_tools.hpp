#pragma once

#include "../protocol.hpp"
#include "../../core/memory.hpp"
#include "../../util/encoding.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

namespace revkit::mcp::tools
{

using json = nlohmann::json;

inline json schema_struct_def()
{
    return json{
        {"name",        "struct_def"},
        {"description", "Inspect a memory region and emit a suggested struct layout (offset + guessed type + value). Helps bootstrap a read_struct field list."},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address", {{"type", "string"},  {"description", "Base address (hex)"}}},
                {"size",    {{"type", "integer"}, {"description", "Region size in bytes"}, {"default", 256}}},
                {"step",    {
                    {"type", "string"}, {"description", "Field stride"},
                    {"enum", json::array({"1","2","4","8"})}, {"default", "4"}
                }}
            }},
            {"required", json::array({"address"})}
        }}
    };
}

inline std::string guess_type(const std::vector<uint8_t>& b)
{
    if (b.size() == 8)
    {
        uintptr_t v = 0;
        for (int i = 0; i < 8; ++i) v |= (uintptr_t)b[i] << (8 * i);
        if ((v & 0xFFFF000000000000ULL) && v > 0x10000)
            return "ptr";
        return "u64";
    }
    if (b.size() == 4)
    {
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= (uint32_t)b[i] << (8 * i);
        if ((v & 0xFFFF0000) && v > 0x1000)
            return "ptr-lo";
        return "u32";
    }
    if (b.size() == 2)
    {
        uint16_t v = 0;
        for (int i = 0; i < 2; ++i) v |= (uint16_t)b[i] << (8 * i);
        return "u16";
    }
    if (b.size() == 1)
        return "u8";
    return "u8";
}

inline json handle_struct_def(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    uintptr_t addr = revkit::util::parse_addr(args["address"].get<std::string>());
    size_t    size = args.contains("size") ? static_cast<size_t>(args["size"].get<int>()) : 256;
    int       step = 4;
    if (args.contains("step") && args["step"].is_string())
    {
        int s = std::stoi(args["step"].get<std::string>());
        if (s == 1 || s == 2 || s == 4 || s == 8) step = s;
    }

    if (size == 0 || size > 0x10000) size = 0x10000;

    auto bytes = mem.read_safe(addr, size);
    if (bytes.empty())
        return tool_err("failed to read memory at " + revkit::util::addr_str(addr));

    json arr = json::array();
    for (size_t off = 0; off + (size_t)step <= bytes.size(); off += step)
    {
        std::vector<uint8_t> chunk(bytes.begin() + off, bytes.begin() + off + step);
        std::string val_hex = revkit::util::to_hex(chunk.data(), chunk.size(), false);

        std::string value;
        if (step == 8)
        {
            uint64_t v = 0;
            for (int i = 0; i < 8; ++i) v |= (uint64_t)chunk[i] << (8 * i);
            value = revkit::util::addr_str(v);
        }
        else if (step == 4)
        {
            uint32_t v = 0;
            for (int i = 0; i < 4; ++i) v |= (uint32_t)chunk[i] << (8 * i);
            value = std::to_string(v);
        }
        else if (step == 2)
        {
            uint16_t v = 0;
            for (int i = 0; i < 2; ++i) v |= (uint16_t)chunk[i] << (8 * i);
            value = std::to_string(v);
        }
        else
        {
            value = std::to_string(chunk[0]);
        }

        arr.push_back({
            {"offset", revkit::util::addr_str(addr + off)},
            {"type",   guess_type(chunk)},
            {"hex",    val_hex},
            {"value",  value}
        });
    }

    return tool_ok(json{
        {"base",   revkit::util::addr_str(addr)},
        {"step",   step},
        {"count",  arr.size()},
        {"layout", arr}
    });
}

}
