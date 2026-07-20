#pragma once

#include "../protocol.hpp"
#include "../../core/memory.hpp"
#include "../../analysis/struct.hpp"
#include "../../util/encoding.hpp"
#include <string>
#include <vector>

namespace revkit::mcp::tools
{

using json = nlohmann::json;

inline json schema_read_struct()
{
    return json{
        {"name",        "read_struct"},
        {"description", "Read and decode a struct at an address using a field layout (offset + type). Returns typed values per field."},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address", {{"type", "string"}, {"description", "Base address (hex)"}}},
                {"fields",  {
                    {"type", "array"},
                    {"description", "Field layout"},
                    {"items", {
                        {"type", "object"},
                        {"properties", {
                            {"name",   {{"type", "string"}}},
                            {"offset", {{"type", "integer"}, {"description", "Offset from base"}}},
                            {"type",   {{"type", "string"}, {"enum", json::array({
                                "u8","i8","u16","i16","u32","i32","u64","i64",
                                "f32","f64","ptr","bool","str","utf16","vec2","vec3"
                            })}}},
                            {"length", {{"type", "integer"}, {"description", "Bytes for str/utf16"}}},
                            {"count",  {{"type", "integer"}, {"description", "Array count (default 1)"}}}
                        }},
                        {"required", json::array({"name", "offset", "type"})}
                    }}
                }}
            }},
            {"required", json::array({"address", "fields"})}
        }}
    };
}

inline json handle_read_struct(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    uintptr_t base = revkit::util::parse_addr(args["address"].get<std::string>());

    std::vector<revkit::analysis::StructField> fields;
    for (const auto& f : args["fields"])
    {
        revkit::analysis::StructField sf{};
        sf.name   = f.value("name", "");
        sf.offset = static_cast<uintptr_t>(f.value("offset", 0));
        sf.type   = f.value("type", "u32");
        sf.length = f.value("length", 0);
        sf.count  = f.value("count", 1);
        fields.push_back(sf);
    }

    auto vals = revkit::analysis::read_struct(base, fields);

    json arr = json::array();
    for (const auto& v : vals)
    {
        arr.push_back({
            {"name",   v.name},
            {"offset", revkit::util::addr_str(v.offset)},
            {"type",   v.type},
            {"value",  v.value}
        });
    }

    return tool_ok(json{
        {"base",   revkit::util::addr_str(base)},
        {"count",  vals.size()},
        {"fields", arr}
    });
}

}
