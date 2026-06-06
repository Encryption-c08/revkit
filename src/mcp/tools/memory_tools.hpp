#pragma once

#include "../protocol.hpp"
#include "../../core/memory.hpp"
#include "../../analysis/scanner.hpp"
#include "../../analysis/chain.hpp"
#include "../../util/encoding.hpp"
#include <Windows.h>
#include <string>
#include <vector>
#include <cctype>

namespace revkit::mcp::tools
{

using json = nlohmann::json;

namespace detail
{

inline std::string protect_str(DWORD p)
{
    p &= ~static_cast<DWORD>(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    switch (p)
    {
        case PAGE_NOACCESS:           return "NOACCESS";
        case PAGE_READONLY:           return "READONLY";
        case PAGE_READWRITE:          return "READWRITE";
        case PAGE_WRITECOPY:          return "WRITECOPY";
        case PAGE_EXECUTE:            return "EXECUTE";
        case PAGE_EXECUTE_READ:       return "EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE:  return "EXECUTE_READWRITE";
        case PAGE_EXECUTE_WRITECOPY:  return "EXECUTE_WRITECOPY";
        default:                      return "UNKNOWN(" + std::to_string(p) + ")";
    }
}

inline std::string state_str(DWORD s)
{
    switch (s)
    {
        case MEM_COMMIT:  return "commit";
        case MEM_RESERVE: return "reserve";
        case MEM_FREE:    return "free";
        default:          return "unknown";
    }
}

inline std::string type_str(DWORD t)
{
    switch (t)
    {
        case MEM_IMAGE:   return "image";
        case MEM_MAPPED:  return "mapped";
        case MEM_PRIVATE: return "private";
        default:          return "unknown";
    }
}

inline std::vector<uint8_t> parse_hex_bytes(const std::string& hex)
{
    std::string stripped;
    stripped.reserve(hex.size());
    for (char c : hex)
    {
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            stripped += c;
    }

    std::vector<uint8_t> out;
    if (stripped.size() % 2 != 0)
        return out;

    out.reserve(stripped.size() / 2);
    for (size_t i = 0; i < stripped.size(); i += 2)
    {
        char hi = static_cast<char>(std::toupper(static_cast<unsigned char>(stripped[i])));
        char lo = static_cast<char>(std::toupper(static_cast<unsigned char>(stripped[i + 1])));

        auto hex_val = [](char c) -> int
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };

        int h = hex_val(hi);
        int l = hex_val(lo);
        if (h < 0 || l < 0)
            return {};

        out.push_back(static_cast<uint8_t>((h << 4) | l));
    }
    return out;
}

}

inline json schema_memory_read()
{
    return json{
        {"name",        "memory_read"},
        {"description", "Read memory from the attached process"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address", {{"type", "string"},  {"description", "Address (hex string)"}}},
                {"size",    {{"type", "integer"}, {"description", "Number of bytes to read"}}},
                {"format",  {{"type", "string"},  {"description", "Output format"},
                              {"enum", json::array({"hexdump", "hex", "base64"})},
                              {"default", "hexdump"}}}
            }},
            {"required", json::array({"address", "size"})}
        }}
    };
}

inline json handle_memory_read(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    uintptr_t addr = revkit::util::parse_addr(args["address"].get<std::string>());
    size_t    sz   = static_cast<size_t>(args["size"].get<int>());
    if (sz > 65536)
        sz = 65536;

    std::string fmt = "hexdump";
    if (args.contains("format") && args["format"].is_string())
        fmt = args["format"].get<std::string>();

    auto bytes = mem.read_safe(addr, sz);
    if (bytes.empty())
        return tool_err("failed to read memory at " + revkit::util::addr_str(addr));

    std::string output;
    if (fmt == "hex")
    {
        output = revkit::util::to_hex(bytes.data(), bytes.size(), true);
    }
    else if (fmt == "base64")
    {
        output = revkit::util::to_base64(bytes.data(), bytes.size());
    }
    else
    {
        output = revkit::util::hex_dump(bytes.data(), bytes.size(), addr);
    }

    return tool_ok(output);
}

inline json schema_memory_write_physical()
{
    return json{
        {"name",        "memory_write_physical"},
        {"description", "Write bytes directly to physical RAM via PTE manipulation — bypasses all kernel API monitoring, most stealthy write method available"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address", {{"type", "string"}, {"description", "Target virtual address in attached process (hex)"}}},
                {"bytes",   {{"type", "string"}, {"description", "Hex bytes to write e.g. \"C8 00 00 00\""}}}
            }},
            {"required", json::array({"address", "bytes"})}
        }}
    };
}

inline json handle_memory_write_physical(const json& args)
{
    auto& drv = revkit::driver::DriverMemory::get();
    if (!drv.is_open())
        return tool_err("kernel driver not open — run as admin");
    if (!drv.is_attached())
        return tool_err("not attached — call process_attach first");

    uintptr_t addr = revkit::util::parse_addr(args["address"].get<std::string>());
    auto bytes = detail::parse_hex_bytes(args["bytes"].get<std::string>());
    if (bytes.empty())
        return tool_err("failed to parse hex bytes");
    if (bytes.size() > 4096)
        return tool_err("max 4096 bytes per physical write");

    if (!drv.write_physical(addr, bytes.data(), bytes.size()))
        return tool_err("physical write failed at " + revkit::util::addr_str(addr));

    return tool_ok(json{
        {"message",       "physical write ok"},
        {"address",       revkit::util::addr_str(addr)},
        {"bytes_written", bytes.size()},
        {"method",        "PTE/MmMapIoSpaceEx"}
    });
}

inline json schema_memory_write()
{
    return json{
        {"name",        "memory_write"},
        {"description", "Write bytes to process memory"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address", {{"type", "string"}, {"description", "Target address (hex string)"}}},
                {"bytes",   {{"type", "string"}, {"description", "Hex bytes e.g. \"48 8B C0\" or \"488BC0\""}}}
            }},
            {"required", json::array({"address", "bytes"})}
        }}
    };
}

inline json handle_memory_write(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    uintptr_t addr = revkit::util::parse_addr(args["address"].get<std::string>());
    std::string hex_str = args["bytes"].get<std::string>();

    auto bytes = detail::parse_hex_bytes(hex_str);
    if (bytes.empty())
        return tool_err("failed to parse hex bytes");

    if (!mem.write(addr, bytes.data(), bytes.size()))
        return tool_err("write failed at " + revkit::util::addr_str(addr));

    return tool_ok(json{
        {"message",       "ok"},
        {"bytes_written", bytes.size()}
    });
}

inline json schema_memory_query()
{
    return json{
        {"name",        "memory_query"},
        {"description", "Query a memory region at the given address"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address", {{"type", "string"}, {"description", "Address to query"}}}
            }},
            {"required", json::array({"address"})}
        }}
    };
}

inline json handle_memory_query(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    uintptr_t addr = revkit::util::parse_addr(args["address"].get<std::string>());
    auto region = mem.query(addr);
    if (!region)
        return tool_err("VirtualQueryEx failed for " + revkit::util::addr_str(addr));

    return tool_ok(json{
        {"base",    revkit::util::addr_str(region->base)},
        {"size",    region->size},
        {"state",   detail::state_str(region->state)},
        {"type",    detail::type_str(region->type)},
        {"protect", detail::protect_str(region->protect)}
    });
}

inline json schema_memory_regions()
{
    return json{
        {"name",        "memory_regions"},
        {"description", "Enumerate committed memory regions in the attached process"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"filter", {
                    {"type",    "string"},
                    {"description", "Filter by region type"},
                    {"enum",    json::array({"all", "image", "mapped", "private"})},
                    {"default", "all"}
                }}
            }},
            {"required", json::array()}
        }}
    };
}

inline json handle_memory_regions(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    std::string filter = "all";
    if (args.contains("filter") && args["filter"].is_string())
        filter = args["filter"].get<std::string>();

    auto regions = mem.regions();
    json arr = json::array();

    for (const auto& r : regions)
    {
        if (r.state != MEM_COMMIT)
            continue;

        if (filter == "image"   && r.type != MEM_IMAGE)   continue;
        if (filter == "mapped"  && r.type != MEM_MAPPED)  continue;
        if (filter == "private" && r.type != MEM_PRIVATE) continue;

        arr.push_back({
            {"base",    revkit::util::addr_str(r.base)},
            {"size",    r.size},
            {"type",    detail::type_str(r.type)},
            {"protect", detail::protect_str(r.protect)}
        });
    }

    return tool_ok(arr);
}

inline json schema_memory_scan()
{
    return json{
        {"name",        "memory_scan"},
        {"description", "Scan process memory for a byte pattern (IDA-style, ?? wildcards)"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"pattern",     {{"type", "string"},  {"description", "IDA pattern e.g. \"48 8B ?? 05 ??\"" }}},
                {"max_results", {{"type", "integer"}, {"description", "Max matches to return"}, {"default", 50}}},
                {"start",       {{"type", "string"},  {"description", "Start address for range scan"}}},
                {"size",        {{"type", "integer"}, {"description", "Size for range scan"}}}
            }},
            {"required", json::array({"pattern"})}
        }}
    };
}

inline json handle_memory_scan(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    std::string pattern = args["pattern"].get<std::string>();
    size_t max_results  = 50;
    if (args.contains("max_results") && args["max_results"].is_number_integer())
        max_results = static_cast<size_t>(args["max_results"].get<int>());

    std::vector<revkit::analysis::Match> matches;

    bool has_start = args.contains("start") && !args["start"].is_null();
    bool has_size  = args.contains("size")  && !args["size"].is_null();

    if (has_start && has_size)
    {
        uintptr_t start = revkit::util::parse_addr(args["start"].get<std::string>());
        size_t    sz    = static_cast<size_t>(args["size"].get<int>());
        matches = revkit::analysis::scan_range(start, sz, pattern);
        if (matches.size() > max_results)
            matches.resize(max_results);
    }
    else
    {
        matches = revkit::analysis::scan_process(pattern, max_results);
    }

    json arr = json::array();
    for (const auto& m : matches)
        arr.push_back({{"address", revkit::util::addr_str(m.address)}});

    return tool_ok(json{
        {"count",   matches.size()},
        {"matches", arr}
    });
}

inline json schema_pointer_chain()
{
    return json{
        {"name",        "pointer_chain"},
        {"description", "Resolve a multi-level pointer chain"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"base",    {{"type", "string"}, {"description", "Base address"}}},
                {"offsets", {{"type", "array"},  {"description", "Array of integer offsets"},
                              {"items", {{"type", "integer"}}}}}
            }},
            {"required", json::array({"base", "offsets"})}
        }}
    };
}

inline json handle_pointer_chain(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    uintptr_t base = revkit::util::parse_addr(args["base"].get<std::string>());

    std::vector<ptrdiff_t> offsets;
    for (const auto& item : args["offsets"])
        offsets.push_back(static_cast<ptrdiff_t>(item.get<int64_t>()));

    auto resolved = revkit::analysis::resolve_chain(base, offsets);
    if (!resolved)
        return tool_err("pointer chain resolution failed");

    auto val = mem.read_val<uintptr_t>(*resolved);

    json result{
        {"resolved", revkit::util::addr_str(*resolved)}
    };
    if (val)
        result["value"] = revkit::util::addr_str(*val);
    else
        result["value"] = nullptr;

    return tool_ok(result);
}

}
