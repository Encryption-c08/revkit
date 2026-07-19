#pragma once

#include "../protocol.hpp"
#include "../../core/memory.hpp"
#include "../../core/process.hpp"
#include "../../analysis/pe.hpp"
#include "../../analysis/scanner.hpp"
#include "../../analysis/disasm.hpp"
#include "../../util/encoding.hpp"
#include <Windows.h>
#include <string>
#include <vector>
#include <cstring>
#include <optional>
#include <algorithm>
#include <sstream>

namespace revkit::mcp::tools
{

using json = nlohmann::json;

inline json schema_disassemble()
{
    return json{
        {"name",        "disassemble"},
        {"description", "Disassemble instructions at an address in the attached process"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address", {{"type", "string"},  {"description", "Start address (hex)"}}},
                {"count",   {{"type", "integer"}, {"description", "Number of instructions to disassemble"}, {"default", 20}}}
            }},
            {"required", json::array({"address"})}
        }}
    };
}

inline json handle_disassemble(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    if (!args.contains("address") || !args["address"].is_string())
        return tool_err("address required");

    uintptr_t addr = revkit::util::parse_addr(args["address"].get<std::string>());

    size_t count = 20;
    if (args.contains("count") && args["count"].is_number_integer())
    {
        int c = args["count"].get<int>();
        if (c > 0 && c <= 256) count = static_cast<size_t>(c);
    }

    auto insns = revkit::analysis::disassemble(addr, count);
    if (insns.empty())
        return tool_err("failed to read memory at " + revkit::util::addr_str(addr));

    json arr = json::array();
    for (const auto& ins : insns)
    {
        arr.push_back({
            {"address",  revkit::util::addr_str(ins.address)},
            {"length",   ins.length},
            {"bytes",    ins.bytes_hex},
            {"mnemonic", ins.mnemonic}
        });
    }

    return tool_ok(json{
        {"address", revkit::util::addr_str(addr)},
        {"count",   insns.size()},
        {"insns",   arr}
    });
}

inline json schema_disassemble_function()
{
    return json{
        {"name",        "disassemble_function"},
        {"description", "Disassemble a whole function: walk linearly from a start address until a terminating instruction (ret/int3/ud2). Returns every instruction in the body."},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address",   {{"type", "string"},  {"description", "Start address (hex)"}}},
                {"max_insns", {{"type", "integer"}, {"description", "Max instructions to decode"}, {"default", 1024}}}
            }},
            {"required", json::array({"address"})}
        }}
    };
}

inline json handle_disassemble_function(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    if (!args.contains("address") || !args["address"].is_string())
        return tool_err("address required");

    uintptr_t addr = revkit::util::parse_addr(args["address"].get<std::string>());

    size_t max_insns = 1024;
    if (args.contains("max_insns") && args["max_insns"].is_number_integer())
    {
        int m = args["max_insns"].get<int>();
        if (m > 0 && m <= 8192) max_insns = static_cast<size_t>(m);
    }

    auto insns = revkit::analysis::disassemble_function(addr, max_insns);
    if (insns.empty())
        return tool_err("failed to read memory at " + revkit::util::addr_str(addr));

    json arr = json::array();
    for (const auto& ins : insns)
    {
        arr.push_back({
            {"address",  revkit::util::addr_str(ins.address)},
            {"length",   ins.length},
            {"bytes",    ins.bytes_hex},
            {"mnemonic", ins.mnemonic}
        });
    }

    return tool_ok(json{
        {"address", revkit::util::addr_str(addr)},
        {"count",   insns.size()},
        {"insns",   arr}
    });
}

inline json schema_value_scan()
{
    return json{
        {"name",        "value_scan"},
        {"description", "Scan process memory for a specific integer or float value"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"value", {{"type", "number"}, {"description", "Value to scan for"}}},
                {"type",  {
                    {"type",        "string"},
                    {"description", "Value type: i32, u32, i64, u64, f32, f64"},
                    {"enum",        json::array({"i32","u32","i64","u64","f32","f64"})},
                    {"default",     "i32"}
                }},
                {"max_results", {{"type", "integer"}, {"description", "Max results to return"}, {"default", 256}}}
            }},
            {"required", json::array({"value"})}
        }}
    };
}

inline json handle_value_scan(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    if (!args.contains("value") || !args["value"].is_number())
        return tool_err("value required");

    std::string type_str = "i32";
    if (args.contains("type") && args["type"].is_string())
        type_str = args["type"].get<std::string>();

    size_t max_results = 256;
    if (args.contains("max_results") && args["max_results"].is_number_integer())
    {
        int mr = args["max_results"].get<int>();
        if (mr > 0 && mr <= 4096) max_results = static_cast<size_t>(mr);
    }

    uint8_t val_buf[8]{};
    size_t  val_size = 4;

    if (type_str == "i32")
    {
        int32_t v = static_cast<int32_t>(args["value"].get<double>());
        std::memcpy(val_buf, &v, 4);
        val_size = 4;
    }
    else if (type_str == "u32")
    {
        uint32_t v = static_cast<uint32_t>(args["value"].get<double>());
        std::memcpy(val_buf, &v, 4);
        val_size = 4;
    }
    else if (type_str == "i64")
    {
        int64_t v = static_cast<int64_t>(args["value"].get<double>());
        std::memcpy(val_buf, &v, 8);
        val_size = 8;
    }
    else if (type_str == "u64")
    {
        uint64_t v = static_cast<uint64_t>(args["value"].get<double>());
        std::memcpy(val_buf, &v, 8);
        val_size = 8;
    }
    else if (type_str == "f32")
    {
        float v = static_cast<float>(args["value"].get<double>());
        std::memcpy(val_buf, &v, 4);
        val_size = 4;
    }
    else if (type_str == "f64")
    {
        double v = args["value"].get<double>();
        std::memcpy(val_buf, &v, 8);
        val_size = 8;
    }
    else
    {
        return tool_err("unsupported type: " + type_str);
    }

    std::string pattern;
    for (size_t i = 0; i < val_size; ++i)
    {
        if (!pattern.empty()) pattern += ' ';
        static const char hex_chars[] = "0123456789ABCDEF";
        pattern += hex_chars[(val_buf[i] >> 4) & 0xF];
        pattern += hex_chars[val_buf[i] & 0xF];
    }

    auto matches = revkit::analysis::scan_process(pattern, max_results);

    json arr = json::array();
    for (const auto& m : matches)
    {
        arr.push_back(revkit::util::addr_str(m.address));
    }

    return tool_ok(json{
        {"type",    type_str},
        {"count",   matches.size()},
        {"results", arr}
    });
}

inline json schema_xref_scan()
{
    return json{
        {"name",        "xref_scan"},
        {"description", "Scan process memory for references (call/jmp/lea) to a target address"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address",     {{"type", "string"},  {"description", "Target address to find references to"}}},
                {"module",      {{"type", "string"},  {"description", "Limit scan to this module name"}}},
                {"max_results", {{"type", "integer"}, {"description", "Max results"}, {"default", 128}}}
            }},
            {"required", json::array({"address"})}
        }}
    };
}

inline json handle_xref_scan(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    if (!args.contains("address") || !args["address"].is_string())
        return tool_err("address required");

    uintptr_t target = revkit::util::parse_addr(args["address"].get<std::string>());

    size_t max_results = 128;
    if (args.contains("max_results") && args["max_results"].is_number_integer())
    {
        int mr = args["max_results"].get<int>();
        if (mr > 0 && mr <= 2048) max_results = static_cast<size_t>(mr);
    }

    std::vector<std::pair<uintptr_t, size_t>> scan_ranges;

    if (args.contains("module") && args["module"].is_string())
    {
        std::string modname = args["module"].get<std::string>();
        auto mod = revkit::core::find_module(mem.pid(), modname);
        if (!mod)
            return tool_err("module not found: " + modname);
        scan_ranges.push_back({mod->base, mod->size});
    }
    else
    {
        for (const auto& r : mem.regions())
        {
            if (r.state == MEM_COMMIT &&
                (r.protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            {
                scan_ranges.push_back({r.base, r.size});
            }
        }
    }

    json arr = json::array();
    size_t found = 0;

    for (const auto& [base, size] : scan_ranges)
    {
        if (found >= max_results) break;

        static constexpr size_t k_chunk = 0x10000;
        size_t offset = 0;

        while (offset + 5 <= size && found < max_results)
        {
            size_t batch = std::min(k_chunk + 4, size - offset);
            auto bytes = mem.read_safe(base + offset, batch);
            if (bytes.size() < 5) { offset += batch; continue; }

            for (size_t i = 0; i + 4 < bytes.size() && found < max_results; ++i)
            {
                uint8_t op = bytes[i];
                bool is_call = (op == 0xE8);
                bool is_jmp  = (op == 0xE9);
                bool is_lea  = false;

                if (!is_call && !is_jmp)
                {
                    if (i + 6 < bytes.size() && bytes[i] == 0x48 && bytes[i+1] == 0x8D)
                        is_lea = true;
                    else if (bytes[i] == 0x4C && bytes[i+1] == 0x8D)
                        is_lea = true;
                    else if (bytes[i] == 0x4D && bytes[i+1] == 0x8D)
                        is_lea = true;
                    else if (bytes[i] == 0x49 && bytes[i+1] == 0x8D)
                        is_lea = true;
                }

                if (is_call || is_jmp)
                {
                    int32_t rel32 = 0;
                    std::memcpy(&rel32, bytes.data() + i + 1, 4);
                    uintptr_t va = base + offset + i;
                    uintptr_t dest = va + 5 + static_cast<uintptr_t>(static_cast<int64_t>(rel32));
                    if (dest == target)
                    {
                        arr.push_back({
                            {"from",    revkit::util::addr_str(va)},
                            {"type",    is_call ? "call" : "jmp"}
                        });
                        ++found;
                    }
                }
                else if (is_lea)
                {
                    size_t instr_start = i;
                    size_t modrm_off   = i + 2;
                    if (modrm_off + 4 < bytes.size())
                    {
                        int32_t rel32 = 0;
                        std::memcpy(&rel32, bytes.data() + modrm_off + 1, 4);
                        uintptr_t va   = base + offset + instr_start;
                        uintptr_t dest = va + 7 + static_cast<uintptr_t>(static_cast<int64_t>(rel32));
                        if (dest == target)
                        {
                            arr.push_back({
                                {"from", revkit::util::addr_str(va)},
                                {"type", "lea"}
                            });
                            ++found;
                        }
                    }
                }
            }

            if (batch <= 4) break;
            offset += batch - 4;
        }
    }

    return tool_ok(json{
        {"target",  revkit::util::addr_str(target)},
        {"count",   found},
        {"xrefs",   arr}
    });
}

inline json schema_module_info_full()
{
    return json{
        {"name",        "module_info_full"},
        {"description", "Get comprehensive module info: PE header, sections, exports, imports, and memory regions"},
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

inline json handle_module_info_full(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    std::optional<uintptr_t> base_opt;
    std::string mod_name;
    std::string mod_path;
    size_t      mod_size = 0;

    if (args.contains("base") && args["base"].is_string() && !args["base"].get<std::string>().empty())
    {
        base_opt = revkit::util::parse_addr(args["base"].get<std::string>());
    }

    if (!base_opt && args.contains("module") && args["module"].is_string())
    {
        mod_name = args["module"].get<std::string>();
        auto mod = revkit::core::find_module(mem.pid(), mod_name);
        if (!mod)
            return tool_err("module not found: " + mod_name);
        base_opt = mod->base;
        mod_path = mod->path;
        mod_size = mod->size;
    }

    if (!base_opt)
        return tool_err("provide module name or base address");

    uintptr_t base = *base_opt;

    if (mod_name.empty())
    {
        auto mods = revkit::core::list_modules(mem.pid());
        for (const auto& m : mods)
        {
            if (m.base == base)
            {
                mod_name = m.name;
                mod_path = m.path;
                mod_size = m.size;
                break;
            }
        }
    }

    json result = json::object();
    result["base"]     = revkit::util::addr_str(base);
    result["name"]     = mod_name;
    result["path"]     = mod_path;
    result["size"]     = mod_size;

    auto pe = revkit::analysis::read_pe_info(base);
    if (pe)
    {
        auto machine_str = [](uint16_t m) -> std::string
        {
            if (m == IMAGE_FILE_MACHINE_AMD64) return "x64";
            if (m == IMAGE_FILE_MACHINE_I386)  return "x86";
            return "unknown";
        };

        uintptr_t slide = pe->image_base - pe->preferred_base;
        result["pe"] = json{
            {"image_base",     revkit::util::addr_str(pe->image_base)},
            {"preferred_base", revkit::util::addr_str(pe->preferred_base)},
            {"aslr_slide",     revkit::util::addr_str(slide)},
            {"image_size",     pe->image_size},
            {"ep_rva",         pe->ep_rva},
            {"ep_va",          revkit::util::addr_str(pe->ep_va)},
            {"machine",        machine_str(pe->machine)},
            {"is_64bit",       pe->is_64bit}
        };

        auto sec_flags = [](uint32_t ch) -> std::string
        {
            std::string out;
            if (ch & IMAGE_SCN_MEM_READ)    out += "R";
            if (ch & IMAGE_SCN_MEM_WRITE)   out += "W";
            if (ch & IMAGE_SCN_MEM_EXECUTE) out += "X";
            return out.empty() ? "---" : out;
        };

        json sections = json::array();
        for (const auto& s : pe->sections)
        {
            sections.push_back({
                {"name",     std::string(s.name)},
                {"rva",      s.rva},
                {"va",       revkit::util::addr_str(base + s.rva)},
                {"vsize",    s.vsize},
                {"raw_size", s.raw_size},
                {"flags",    sec_flags(s.characteristics)}
            });
        }
        result["sections"] = sections;
    }

    auto exports = revkit::analysis::read_exports(base);
    json exp_arr = json::array();
    for (const auto& e : exports)
    {
        exp_arr.push_back({
            {"ordinal", e.ordinal},
            {"name",    e.name},
            {"rva",     e.rva},
            {"va",      revkit::util::addr_str(e.va)}
        });
    }
    result["exports"]       = exp_arr;
    result["export_count"]  = exports.size();

    auto imports = revkit::analysis::read_imports(base);
    json imp_arr = json::array();
    for (const auto& dll : imports)
    {
        json funcs = json::array();
        for (const auto& fn : dll.functions)
            funcs.push_back(fn);
        imp_arr.push_back({
            {"dll",       dll.name},
            {"count",     dll.functions.size()},
            {"functions", funcs}
        });
    }
    result["imports"]      = imp_arr;
    result["import_dlls"]  = imports.size();

    json mem_regions = json::array();
    uintptr_t end = base + (mod_size > 0 ? mod_size : 0x10000000ULL);
    for (const auto& r : mem.regions())
    {
        if (r.base >= base && r.base < end)
        {
            auto protect_str = [](DWORD p) -> std::string
            {
                std::string s;
                if (p & PAGE_EXECUTE_READWRITE)  s = "RWX";
                else if (p & PAGE_EXECUTE_READ)  s = "R-X";
                else if (p & PAGE_READWRITE)     s = "RW-";
                else if (p & PAGE_READONLY)      s = "R--";
                else if (p & PAGE_NOACCESS)      s = "---";
                else s = "???";
                if (p & PAGE_GUARD) s += " GUARD";
                return s;
            };
            mem_regions.push_back({
                {"base",    revkit::util::addr_str(r.base)},
                {"size",    r.size},
                {"protect", protect_str(r.protect)},
                {"state",   r.state == MEM_COMMIT ? "commit" : r.state == MEM_RESERVE ? "reserve" : "free"}
            });
        }
    }
    result["memory_regions"] = mem_regions;

    return tool_ok(result);
}

}
