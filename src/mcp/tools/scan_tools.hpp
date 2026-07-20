#pragma once

#include "../protocol.hpp"
#include "../../core/memory.hpp"
#include "../../analysis/scanner.hpp"
#include "../../util/encoding.hpp"
#include <string>
#include <vector>

namespace revkit::mcp::tools
{

using json = nlohmann::json;

inline json schema_search_opcode()
{
    return json{
        {"name",        "search_opcode"},
        {"description", "Scan a module (or whole process) for a byte pattern with IDA-style ?? wildcards. Returns addresses of every match."},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"pattern",     {{"type", "string"},  {"description", "IDA pattern e.g. \"48 8B ?? 05 ?? ?? ?? ??"}}},
                {"module",      {{"type", "string"},  {"description", "Limit to this module name"}}},
                {"max_results", {{"type", "integer"}, {"description", "Max matches"}, {"default", 100}}},
                {"start",       {{"type", "string"},  {"description", "Start address for range scan"}}},
                {"size",        {{"type", "integer"}, {"description", "Size for range scan"}}}
            }},
            {"required", json::array({"pattern"})}
        }}
    };
}

inline json handle_search_opcode(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    std::string pattern = args["pattern"].get<std::string>();
    size_t max_results = 100;
    if (args.contains("max_results") && args["max_results"].is_number_integer())
        max_results = static_cast<size_t>(args["max_results"].get<int>());

    std::vector<revkit::analysis::Match> matches;

    bool has_module = args.contains("module") && args["module"].is_string() && !args["module"].get<std::string>().empty();
    bool has_start  = args.contains("start")  && !args["start"].is_null();
    bool has_size   = args.contains("size")   && !args["size"].is_null();

    if (has_start && has_size)
    {
        uintptr_t start = revkit::util::parse_addr(args["start"].get<std::string>());
        size_t    sz    = static_cast<size_t>(args["size"].get<int>());
        matches = revkit::analysis::scan_range(start, sz, pattern);
    }
    else if (has_module)
    {
        std::string modname = args["module"].get<std::string>();
        auto mod = revkit::core::find_module(mem.pid(), modname);
        if (!mod)
            return tool_err("module not found: " + modname);
        matches = revkit::analysis::scan_range(mod->base, mod->size, pattern);
    }
    else
    {
        matches = revkit::analysis::scan_process(pattern, max_results);
    }

    if (matches.size() > max_results)
        matches.resize(max_results);

    json arr = json::array();
    for (const auto& m : matches)
        arr.push_back({{"address", revkit::util::addr_str(m.address)}});

    return tool_ok(json{
        {"count",   matches.size()},
        {"matches", arr}
    });
}

}
