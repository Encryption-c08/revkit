#pragma once

#include "../protocol.hpp"
#include "../../core/memory.hpp"
#include "../../driver/backend.hpp"
#include "../../util/encoding.hpp"
#include <Windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace revkit::mcp::tools
{

using json = nlohmann::json;

inline json schema_kernel_read()
{
    return json{
        {"name",        "kernel_read"},
        {"description", "Read from kernel virtual address space via the driver (no attached process required). Use for IDT, EPROCESS, ntoskrnl globals, etc."},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address", {{"type", "string"},  {"description", "Kernel virtual address (hex)"}}},
                {"size",    {{"type", "integer"}, {"description", "Bytes to read"}, {"default", 256}}},
                {"format",  {
                    {"type", "string"}, {"description", "Output format"},
                    {"enum", json::array({"hexdump", "hex"})}, {"default", "hexdump"}
                }}
            }},
            {"required", json::array({"address"})}
        }}
    };
}

inline json handle_kernel_read(const json& args)
{
    auto& drv = revkit::driver::DriverMemory::get();
    if (!drv.is_open())
        return tool_err("kernel driver not open — run as admin");

    uintptr_t addr = revkit::util::parse_addr(args["address"].get<std::string>());
    size_t    sz   = args.contains("size") ? static_cast<size_t>(args["size"].get<int>()) : 256;
    if (sz == 0 || sz > 0x400000) sz = 0x400000;

    std::vector<uint8_t> buf(sz, 0);
    size_t got = drv.kernel_read(addr, buf.data(), buf.size());
    if (got == 0)
        return tool_err("kernel read failed at " + revkit::util::addr_str(addr));

    std::string fmt = "hexdump";
    if (args.contains("format") && args["format"].is_string())
        fmt = args["format"].get<std::string>();

    std::string output = (fmt == "hex")
        ? revkit::util::to_hex(buf.data(), got, true)
        : revkit::util::hex_dump(buf.data(), got, addr);

    return tool_ok(json{
        {"address",   revkit::util::addr_str(addr)},
        {"bytes",     got},
        {"data",      output}
    });
}

inline json schema_read_physical()
{
    return json{
        {"name",        "read_physical"},
        {"description", "Read bytes from a virtual address via its physical mapping (MmGetPhysicalAddress + MmMapIoSpaceEx). Bypasses page protections — useful for guarded/protected pages."},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address", {{"type", "string"},  {"description", "Virtual address in attached process (hex)"}}},
                {"size",    {{"type", "integer"}, {"description", "Bytes to read (max 4096)"}, {"default", 64}}},
                {"format",  {
                    {"type", "string"}, {"description", "Output format"},
                    {"enum", json::array({"hexdump", "hex"})}, {"default", "hexdump"}
                }}
            }},
            {"required", json::array({"address"})}
        }}
    };
}

inline json handle_read_physical(const json& args)
{
    auto& drv = revkit::driver::DriverMemory::get();
    if (!drv.is_open())
        return tool_err("kernel driver not open — run as admin");
    if (!drv.is_attached())
        return tool_err("not attached — call process_attach first");

    uintptr_t addr = revkit::util::parse_addr(args["address"].get<std::string>());
    size_t    sz   = args.contains("size") ? static_cast<size_t>(args["size"].get<int>()) : 64;
    if (sz == 0 || sz > 4096) sz = 4096;

    std::vector<uint8_t> buf(sz, 0);
    if (!drv.read_physical(addr, buf.data(), buf.size()))
        return tool_err("physical read failed at " + revkit::util::addr_str(addr));

    std::string fmt = "hexdump";
    if (args.contains("format") && args["format"].is_string())
        fmt = args["format"].get<std::string>();

    std::string output = (fmt == "hex")
        ? revkit::util::to_hex(buf.data(), buf.size(), true)
        : revkit::util::hex_dump(buf.data(), buf.size(), addr);

    return tool_ok(json{
        {"address", revkit::util::addr_str(addr)},
        {"bytes",   buf.size()},
        {"data",    output}
    });
}

inline json schema_driver_status()
{
    return json{
        {"name",        "driver_status"},
        {"description", "Report driver state: open handle, attached pid, and backend in use"},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", json::object()},
            {"required",   json::array()}
        }}
    };
}

inline json handle_driver_status(const json&)
{
    auto& drv = revkit::driver::DriverMemory::get();
    auto& mem = revkit::core::Memory::get();
    return tool_ok(json{
        {"device_open",  drv.is_open()},
        {"attached",     drv.is_attached()},
        {"attached_pid", drv.pid()},
        {"backend",      mem.using_driver() ? "kernel_driver" : "read_process_memory"}
    });
}

}
