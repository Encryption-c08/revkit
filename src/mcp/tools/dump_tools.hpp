#pragma once

#include "../protocol.hpp"
#include "../../core/memory.hpp"
#include "../../core/process.hpp"
#include "../../driver/backend.hpp"
#include "../../util/encoding.hpp"
#include <Windows.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "Psapi.lib")

namespace revkit::mcp::tools
{

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
namespace detail
{

inline std::string default_dump_path(const std::string& name)
{
    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    std::string out = tmp;
    if (out.back() != '\\') out += '\\';
    out += name;
    // swap slashes, remove path separators from module name
    std::replace(out.begin(), out.end(), '/', '\\');
    return out;
}

inline bool write_file(const std::string& path, const std::vector<uint8_t>& data)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    return f.good();
}

// Read IMAGE_NT_HEADERS SizeOfImage from a blob that starts at image base.
// Returns 0 if the header looks invalid.
inline uint32_t pe_image_size(const uint8_t* hdr, size_t hdr_len)
{
    if (hdr_len < 0x40) return 0;
    uint16_t magic = *reinterpret_cast<const uint16_t*>(hdr);
    if (magic != 0x5A4D) return 0;  // MZ
    int32_t  e_lfanew = *reinterpret_cast<const int32_t*>(hdr + 0x3C);
    if (e_lfanew < 0 || (size_t)(e_lfanew + 0x50) > hdr_len) return 0;
    uint32_t sig = *reinterpret_cast<const uint32_t*>(hdr + e_lfanew);
    if (sig != 0x00004550) return 0;  // PE\0\0
    // SizeOfImage is at OptionalHeader offset 0x38 from PE sig in both x86/x64
    uint32_t sz = *reinterpret_cast<const uint32_t*>(hdr + e_lfanew + 0x18 + 0x38);
    return sz;
}

// Case-insensitive find of kernel module base via EnumDeviceDrivers.
// Returns 0 on failure.
inline uintptr_t find_kernel_module(const std::string& name)
{
    LPVOID drivers[4096];
    DWORD  needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) return 0;
    DWORD count = needed / sizeof(LPVOID);
    for (DWORD i = 0; i < count; i++)
    {
        char buf[MAX_PATH];
        if (!GetDeviceDriverBaseNameA(drivers[i], buf, MAX_PATH)) continue;
        std::string cur = buf;
        std::string cmp_cur = cur, cmp_tgt = name;
        std::transform(cmp_cur.begin(), cmp_cur.end(), cmp_cur.begin(), ::tolower);
        std::transform(cmp_tgt.begin(), cmp_tgt.end(), cmp_tgt.begin(), ::tolower);
        if (cmp_cur == cmp_tgt)
            return reinterpret_cast<uintptr_t>(drivers[i]);
    }
    return 0;
}

} // namespace detail

// ---------------------------------------------------------------------------
// dump_module — dump a PE from the attached process to disk
// ---------------------------------------------------------------------------
inline json schema_dump_module()
{
    return json{
        {"name",        "dump_module"},
        {"description", "Dump a loaded PE module from the attached process to a file on disk. "
                        "Useful for extracting packed/protected executables after they unpack in memory. "
                        "Produces a raw memory image that IDA/Ghidra can load directly."},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"module", {{"type", "string"}, {"description", "Module name (e.g. \"target.exe\"). Defaults to main module."}}},
                {"path",   {{"type", "string"}, {"description", "Output file path. Defaults to %TEMP%\\<module_name>.bin"}}}
            }},
            {"required", json::array()}
        }}
    };
}

inline json handle_dump_module(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        throw std::runtime_error("no process attached");

    // resolve module
    std::string modname;
    uintptr_t   base = 0;
    size_t      img_size = 0;

    if (args.contains("module") && args["module"].is_string())
        modname = args["module"].get<std::string>();

    if (!modname.empty())
    {
        auto mod = revkit::core::find_module(mem.pid(), modname);
        if (!mod) throw std::runtime_error("module not found: " + modname);
        base     = mod->base;
        img_size = mod->size;
    }
    else
    {
        auto mods = revkit::core::list_modules(mem.pid());
        if (mods.empty()) throw std::runtime_error("no modules found");
        base     = mods[0].base;
        img_size = mods[0].size;
        modname  = mods[0].name;
    }

    if (img_size == 0 || img_size > 0x20000000)
        throw std::runtime_error("invalid image size: " + std::to_string(img_size));

    // read PE header to confirm and get accurate SizeOfImage
    uint8_t hdr_buf[0x1000];
    if (mem.read(base, hdr_buf, sizeof(hdr_buf)))
    {
        uint32_t pe_sz = detail::pe_image_size(hdr_buf, sizeof(hdr_buf));
        if (pe_sz > 0 && pe_sz <= 0x20000000)
            img_size = pe_sz;
    }

    // read in 64KB chunks — read_safe already handles this but we want progress
    constexpr size_t CHUNK = 0x10000;
    std::vector<uint8_t> image;
    image.reserve(img_size);
    size_t done = 0;
    while (done < img_size)
    {
        size_t batch = (img_size - done < CHUNK) ? img_size - done : CHUNK;
        std::vector<uint8_t> tmp(batch, 0);
        mem.read(base + done, tmp.data(), batch); // partial read ok — section gaps are zero
        image.insert(image.end(), tmp.begin(), tmp.end());
        done += batch;
    }

    // resolve output path
    std::string outpath;
    if (args.contains("path") && args["path"].is_string())
        outpath = args["path"].get<std::string>();
    else
        outpath = detail::default_dump_path(modname + ".bin");

    if (!detail::write_file(outpath, image))
        throw std::runtime_error("failed to write file: " + outpath);

    return json{
        {"module",  modname},
        {"base",    revkit::util::addr_str(base)},
        {"size",    img_size},
        {"bytes",   image.size()},
        {"path",    outpath},
        {"message", "dump complete"}
    };
}

// ---------------------------------------------------------------------------
// kernel_module_dump — dump a kernel module (ntoskrnl, driver, etc.) to disk
// ---------------------------------------------------------------------------
inline json schema_kernel_module_dump()
{
    return json{
        {"name",        "kernel_module_dump"},
        {"description", "Dump a kernel module from ring-0 memory to a file on disk. "
                        "Works on ntoskrnl.exe, hal.dll, loaded drivers, etc. "
                        "No attached process required — reads directly from kernel VA space."},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"module", {{"type", "string"}, {"description", "Kernel module name (e.g. \"ntoskrnl.exe\", \"hal.dll\"). Case-insensitive."}}},
                {"path",   {{"type", "string"}, {"description", "Output file path. Defaults to %TEMP%\\<module_name>.bin"}}}
            }},
            {"required", json::array({"module"})}
        }}
    };
}

inline json handle_kernel_module_dump(const json& args)
{
    auto& drv = revkit::driver::DriverMemory::get();
    if (!drv.is_open())
        throw std::runtime_error("driver not loaded");

    std::string modname = args.value("module", "");
    if (modname.empty())
        throw std::runtime_error("module name required");

    uintptr_t base = detail::find_kernel_module(modname);
    if (!base)
        throw std::runtime_error("kernel module not found: " + modname);

    // read PE header to get SizeOfImage
    uint8_t hdr_buf[0x1000] = {};
    size_t hdr_read = drv.kernel_read(base, hdr_buf, sizeof(hdr_buf));
    if (hdr_read < 0x40)
        throw std::runtime_error("failed to read PE header at " + revkit::util::addr_str(base));

    uint32_t img_size = detail::pe_image_size(hdr_buf, hdr_read);
    if (img_size == 0)
        throw std::runtime_error("invalid PE header at kernel module base");
    if (img_size > 0x20000000) // 512 MB sanity cap
        throw std::runtime_error("image size unreasonably large: " + std::to_string(img_size));

    // dump in 4MB chunks
    constexpr size_t CHUNK = 0x400000;
    std::vector<uint8_t> image(img_size, 0);
    size_t done = 0;
    while (done < img_size)
    {
        size_t batch = (img_size - done < CHUNK) ? img_size - done : CHUNK;
        size_t got = drv.kernel_read(base + done, image.data() + done, batch);
        if (got == 0) break; // access violation — section not present (paged out etc.)
        done += got;
    }

    std::string outpath;
    if (args.contains("path") && args["path"].is_string())
        outpath = args["path"].get<std::string>();
    else
        outpath = detail::default_dump_path(modname + ".bin");

    if (!detail::write_file(outpath, image))
        throw std::runtime_error("failed to write file: " + outpath);

    return json{
        {"module",  modname},
        {"base",    revkit::util::addr_str(base)},
        {"size",    img_size},
        {"bytes",   image.size()},
        {"path",    outpath},
        {"message", "kernel dump complete"}
    };
}

// ---------------------------------------------------------------------------
// dump_memory — raw byte range dump (heap, stack, any region)
// ---------------------------------------------------------------------------
inline json schema_dump_memory()
{
    return json{
        {"name",        "dump_memory"},
        {"description", "Dump a raw memory range from the attached process to a file on disk. "
                        "Use for heap dumps, stack captures, or any arbitrary region."},
        {"inputSchema", {
            {"type",       "object"},
            {"properties", {
                {"address", {{"type", "string"}, {"description", "Start address (hex)"}}},
                {"size",    {{"type", "integer"}, {"description", "Number of bytes to dump"}}},
                {"path",    {{"type", "string"}, {"description", "Output file path. Defaults to %TEMP%\\memdump_<addr>.bin"}}}
            }},
            {"required", json::array({"address", "size"})}
        }}
    };
}

inline json handle_dump_memory(const json& args)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        throw std::runtime_error("no process attached");

    uintptr_t addr = revkit::util::parse_addr(args["address"].get<std::string>());
    size_t    size = args["size"].get<size_t>();

    if (size == 0)      throw std::runtime_error("size must be > 0");
    if (size > 0x40000000) throw std::runtime_error("size too large (max 1 GB)");

    std::vector<uint8_t> data = mem.read_safe(addr, size);
    if (data.empty())
        throw std::runtime_error("failed to read memory at " + revkit::util::addr_str(addr));

    std::string outpath;
    if (args.contains("path") && args["path"].is_string())
        outpath = args["path"].get<std::string>();
    else
    {
        char addr_str[32];
        sprintf_s(addr_str, "memdump_%016llX.bin", static_cast<unsigned long long>(addr));
        outpath = detail::default_dump_path(addr_str);
    }

    if (!detail::write_file(outpath, data))
        throw std::runtime_error("failed to write file: " + outpath);

    return json{
        {"address", revkit::util::addr_str(addr)},
        {"size",    size},
        {"bytes",   data.size()},
        {"path",    outpath},
        {"message", "memory dump complete"}
    };
}

} // namespace revkit::mcp::tools
