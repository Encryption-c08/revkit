#pragma once

#include "../protocol.hpp"
#include "../../core/memory.hpp"
#include "../../core/process.hpp"
#include "../../util/encoding.hpp"

namespace revkit::mcp::tools
{

using json = nlohmann::json;

inline json schema_process_list()
{
    return json{
        {"name",        "process_list"},
        {"description", "List all running processes"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", json::object()},
            {"required",   json::array()}
        }}
    };
}

inline json handle_process_list(const json&)
{
    auto procs = revkit::core::list_processes();
    json arr = json::array();
    for (const auto& p : procs)
    {
        arr.push_back({
            {"pid",        p.pid},
            {"parent_pid", p.parent_pid},
            {"name",       p.name},
            {"path",       p.path}
        });
    }
    return tool_ok(arr);
}

inline json schema_process_attach()
{
    return json{
        {"name",        "process_attach"},
        {"description", "Attach to a process by PID or name"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"pid",  {{"type", "integer"}, {"description", "Process ID"}}},
                {"name", {{"type", "string"},  {"description", "Process name"}}}
            }},
            {"required", json::array()}
        }}
    };
}

inline json handle_process_attach(const json& args)
{
    std::optional<revkit::core::ProcessInfo> info;

    if (args.contains("pid") && !args["pid"].is_null())
    {
        uint32_t pid = args["pid"].get<uint32_t>();
        info = revkit::core::find_process_by_pid(pid);
        if (!info)
            return tool_err("process not found for pid " + std::to_string(pid));
    }
    else if (args.contains("name") && !args["name"].is_null())
    {
        std::string name = args["name"].get<std::string>();
        info = revkit::core::find_process(name);
        if (!info)
            return tool_err("process not found: " + name);
    }
    else
    {
        return tool_err("provide pid or name");
    }

    revkit::core::Memory::get().try_use_driver();

    if (!revkit::core::Memory::get().attach(info->pid))
        return tool_err("failed to attach to pid " + std::to_string(info->pid));

    bool drv = revkit::core::Memory::get().using_driver();

    return tool_ok(json{
        {"message", drv ? "attached [kernel driver]" : "attached [user-mode ReadProcessMemory]"},
        {"pid",     info->pid},
        {"name",    info->name}
    });
}

inline json schema_process_detach()
{
    return json{
        {"name",        "process_detach"},
        {"description", "Detach from the current process"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", json::object()},
            {"required",   json::array()}
        }}
    };
}

inline json handle_process_detach(const json&)
{
    revkit::core::Memory::get().detach();
    return tool_ok(std::string{"detached"});
}

inline json schema_process_status()
{
    return json{
        {"name",        "process_status"},
        {"description", "Get current attach status"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", json::object()},
            {"required",   json::array()}
        }}
    };
}

inline json handle_process_status(const json&)
{
    auto& mem = revkit::core::Memory::get();
    json result{
        {"driver_open", revkit::driver::DriverMemory::get().is_open()},
        {"attached",    mem.is_attached()},
        {"pid",         mem.pid()},
        {"backend",     mem.using_driver() ? "kernel_driver" : "read_process_memory"}
    };
    if (mem.is_attached())
    {
        auto info = revkit::core::find_process_by_pid(mem.pid());
        if (info)
            result["name"] = info->name;
    }
    return tool_ok(result);
}

inline json schema_module_list()
{
    return json{
        {"name",        "module_list"},
        {"description", "List modules in the attached process"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", json::object()},
            {"required",   json::array()}
        }}
    };
}

inline json handle_module_list(const json&)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    auto mods = revkit::core::list_modules(mem.pid());
    json arr = json::array();
    for (const auto& m : mods)
    {
        arr.push_back({
            {"name", m.name},
            {"base", revkit::util::addr_str(m.base)},
            {"size", m.size},
            {"path", m.path}
        });
    }
    return tool_ok(arr);
}

inline json schema_module_find()
{
    return json{
        {"name",        "module_find"},
        {"description", "Find a module by name in the attached process"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"name", {{"type", "string"}, {"description", "Module name"}}}
            }},
            {"required", json::array({"name"})}
        }}
    };
}

inline json handle_module_find(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return tool_err("not attached to a process");

    std::string name = args["name"].get<std::string>();
    auto mod = revkit::core::find_module(mem.pid(), name);
    if (!mod)
        return tool_err("module not found: " + name);

    return tool_ok(json{
        {"name", mod->name},
        {"base", revkit::util::addr_str(mod->base)},
        {"size", mod->size},
        {"path", mod->path}
    });
}

}
