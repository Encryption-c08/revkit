#pragma once

#include "../protocol.hpp"
#include "../../core/memory.hpp"
#include "../../core/process.hpp"
#include "../../analysis/pe.hpp"
#include "../../analysis/strings.hpp"
#include "../../util/encoding.hpp"
#include <Windows.h>
#include <string>
#include <optional>

namespace revkit::mcp::tools
{

using json = nlohmann::json;

namespace detail
{

inline std::optional<uintptr_t> resolve_module_base(const json& args)
{
    if (args.contains("base") && !args["base"].is_null() && args["base"].is_string())
    {
        std::string s = args["base"].get<std::string>();
        if (!s.empty())
            return revkit::util::parse_addr(s);
    }
    if (args.contains("module") && !args["module"].is_null() && args["module"].is_string())
    {
        auto& mem = revkit::core::Memory::get();
        if (!mem.is_attached())
            return std::nullopt;
        std::string modname = args["module"].get<std::string>();
        auto mod = revkit::core::find_module(mem.pid(), modname);
        if (mod)
            return mod->base;
    }
    return std::nullopt;
}

inline std::string machine_str(uint16_t machine)
{
    switch (machine)
    {
        case IMAGE_FILE_MACHINE_AMD64: return "x64";
        case IMAGE_FILE_MACHINE_I386:  return "x86";
        default:                       return "unknown";
    }
}

inline std::string section_flags_str(uint32_t ch)
{
    std::string out;
    if (ch & IMAGE_SCN_MEM_READ)    out += "R";
    if (ch & IMAGE_SCN_MEM_WRITE)   out += "W";
    if (ch & IMAGE_SCN_MEM_EXECUTE) out += "X";
    if (ch & IMAGE_SCN_CNT_CODE)    { if (!out.empty()) out += " "; out += "CODE"; }
    return out.empty() ? "---" : out;
}

}

inline json schema_pe_info()
{
    return json{
        {"name",        "pe_info"},
        {"description", "Read PE header information from a loaded module"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"module", {{"type", "string"}, {"description", "Module name"}}},
                {"base",   {{"type", "string"}, {"description", "Base address (hex)"}}}
            }},
            {"required", json::array()}
        }}
    };
}

inline json handle_pe_info(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    auto base = detail::resolve_module_base(args);
    if (!base)
        return tool_err("provide module name or base address");

    auto info = revkit::analysis::read_pe_info(*base);
    if (!info)
        return tool_err("failed to parse PE at " + revkit::util::addr_str(*base));

    uintptr_t slide = info->image_base - info->preferred_base;

    return tool_ok(json{
        {"image_base",     revkit::util::addr_str(info->image_base)},
        {"preferred_base", revkit::util::addr_str(info->preferred_base)},
        {"aslr_slide",     revkit::util::addr_str(slide)},
        {"image_size",     info->image_size},
        {"ep_rva",         info->ep_rva},
        {"ep_va",          revkit::util::addr_str(info->ep_va)},
        {"machine",        detail::machine_str(info->machine)},
        {"section_count",  info->sections.size()},
        {"is_64bit",       info->is_64bit}
    });
}

inline json schema_pe_exports()
{
    return json{
        {"name",        "pe_exports"},
        {"description", "Read PE export table from a loaded module"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"module", {{"type", "string"}, {"description", "Module name"}}},
                {"base",   {{"type", "string"}, {"description", "Base address (hex)"}}}
            }},
            {"required", json::array()}
        }}
    };
}

inline json handle_pe_exports(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    auto base = detail::resolve_module_base(args);
    if (!base)
        return tool_err("provide module name or base address");

    auto exports = revkit::analysis::read_exports(*base);

    json arr = json::array();
    for (const auto& e : exports)
    {
        arr.push_back({
            {"ordinal", e.ordinal},
            {"name",    e.name},
            {"rva",     e.rva},
            {"va",      revkit::util::addr_str(e.va)}
        });
    }

    return tool_ok(json{
        {"count",   exports.size()},
        {"exports", arr}
    });
}

inline json schema_pe_imports()
{
    return json{
        {"name",        "pe_imports"},
        {"description", "Read PE import table from a loaded module"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"module", {{"type", "string"}, {"description", "Module name"}}},
                {"base",   {{"type", "string"}, {"description", "Base address (hex)"}}}
            }},
            {"required", json::array()}
        }}
    };
}

inline json handle_pe_imports(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    auto base = detail::resolve_module_base(args);
    if (!base)
        return tool_err("provide module name or base address");

    auto imports = revkit::analysis::read_imports(*base);

    json arr = json::array();
    for (const auto& dll : imports)
    {
        json funcs = json::array();
        for (const auto& fn : dll.functions)
            funcs.push_back(fn);

        arr.push_back({
            {"dll",       dll.name},
            {"count",     dll.functions.size()},
            {"functions", funcs}
        });
    }

    return tool_ok(json{
        {"dll_count", imports.size()},
        {"imports",   arr}
    });
}

inline json schema_pe_sections()
{
    return json{
        {"name",        "pe_sections"},
        {"description", "List PE sections from a loaded module"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"module", {{"type", "string"}, {"description", "Module name"}}},
                {"base",   {{"type", "string"}, {"description", "Base address (hex)"}}}
            }},
            {"required", json::array()}
        }}
    };
}

inline json handle_pe_sections(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    auto base = detail::resolve_module_base(args);
    if (!base)
        return tool_err("provide module name or base address");

    auto info = revkit::analysis::read_pe_info(*base);
    if (!info)
        return tool_err("failed to parse PE at " + revkit::util::addr_str(*base));

    json arr = json::array();
    for (const auto& sec : info->sections)
    {
        uintptr_t va = *base + sec.rva;
        arr.push_back({
            {"name",     std::string(sec.name)},
            {"rva",      sec.rva},
            {"va",       revkit::util::addr_str(va)},
            {"vsize",    sec.vsize},
            {"raw_size", sec.raw_size},
            {"flags",    detail::section_flags_str(sec.characteristics)}
        });
    }

    return tool_ok(arr);
}

inline json schema_string_scan()
{
    return json{
        {"name",        "string_scan"},
        {"description", "Scan a memory region for printable strings"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address",  {{"type", "string"},  {"description", "Start address"}}},
                {"size",     {{"type", "integer"}, {"description", "Region size in bytes"}}},
                {"min_len",  {{"type", "integer"}, {"description", "Minimum string length"}, {"default", 8}}},
                {"encoding", {
                    {"type",        "string"},
                    {"description", "String encoding to scan for"},
                    {"enum",        json::array({"ascii", "utf16", "both"})},
                    {"default",     "both"}
                }}
            }},
            {"required", json::array({"address", "size"})}
        }}
    };
}

inline json handle_string_scan(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    uintptr_t addr = revkit::util::parse_addr(args["address"].get<std::string>());
    size_t    sz   = static_cast<size_t>(args["size"].get<int>());

    size_t min_len = 8;
    if (args.contains("min_len") && args["min_len"].is_number_integer())
        min_len = static_cast<size_t>(args["min_len"].get<int>());

    std::string enc_str = "both";
    if (args.contains("encoding") && args["encoding"].is_string())
        enc_str = args["encoding"].get<std::string>();

    revkit::analysis::StrEncoding enc = revkit::analysis::StrEncoding::Both;
    if (enc_str == "ascii")  enc = revkit::analysis::StrEncoding::ASCII;
    if (enc_str == "utf16")  enc = revkit::analysis::StrEncoding::UTF16LE;

    auto found = revkit::analysis::find_strings(addr, sz, enc, min_len);

    json arr = json::array();
    for (const auto& s : found)
    {
        std::string enc_name;
        switch (s.enc)
        {
            case revkit::analysis::StrEncoding::ASCII:   enc_name = "ascii";  break;
            case revkit::analysis::StrEncoding::UTF16LE: enc_name = "utf16";  break;
            default:                                       enc_name = "unknown"; break;
        }
        arr.push_back({
            {"address",  revkit::util::addr_str(s.address)},
            {"value",    s.value},
            {"encoding", enc_name}
        });
    }

    return tool_ok(json{
        {"count",   found.size()},
        {"strings", arr}
    });
}

}
