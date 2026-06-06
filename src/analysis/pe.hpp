#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <algorithm>
#include <unordered_map>
#include <cstring>
#include "../core/memory.hpp"

namespace revkit::analysis
{

struct PeSection
{
    char     name[9];
    uint32_t rva;
    uint32_t vsize;
    uint32_t raw_off;
    uint32_t raw_size;
    uint32_t characteristics;
};

struct PeExport
{
    uint32_t    ordinal;
    uint32_t    rva;
    uintptr_t   va;
    std::string name;
};

struct PeImportDll
{
    std::string              name;
    std::vector<std::string> functions;
};

struct PeInfo
{
    uintptr_t              image_base;
    uintptr_t              preferred_base;
    uint32_t               image_size;
    uint32_t               ep_rva;
    uintptr_t              ep_va;
    uint16_t               machine;
    bool                   is_64bit;
    std::vector<PeSection> sections;
};

namespace detail
{

static constexpr uint32_t k_max_sections      = 256;
static constexpr uint32_t k_max_exports       = 0x10000;
static constexpr uint32_t k_max_import_dlls   = 512;
static constexpr uint32_t k_max_import_funcs  = 0x10000;
static constexpr uint32_t k_max_name_len      = 256;
static constexpr uint32_t k_image_ordinal_flag32 = 0x80000000u;
static constexpr uint64_t k_image_ordinal_flag64 = 0x8000000000000000ull;
static constexpr uint32_t k_data_dir_count    = 16;

inline IMAGE_DATA_DIRECTORY get_data_dir(uintptr_t base, bool is64, uintptr_t nt_addr, uint32_t index)
{
    IMAGE_DATA_DIRECTORY empty{};
    if (index >= k_data_dir_count)
        return empty;

    auto& mem = revkit::core::Memory::get();

    if (is64)
    {
        constexpr size_t k_optional64_data_dirs_offset =
            offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
            offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
        uintptr_t dir_addr = nt_addr + k_optional64_data_dirs_offset
                             + index * sizeof(IMAGE_DATA_DIRECTORY);
        auto val = mem.read_val<IMAGE_DATA_DIRECTORY>(dir_addr);
        return val.value_or(empty);
    }
    else
    {
        constexpr size_t k_optional32_data_dirs_offset =
            offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
            offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
        uintptr_t dir_addr = nt_addr + k_optional32_data_dirs_offset
                             + index * sizeof(IMAGE_DATA_DIRECTORY);
        auto val = mem.read_val<IMAGE_DATA_DIRECTORY>(dir_addr);
        return val.value_or(empty);
    }
}

inline std::string read_cstr(uintptr_t addr)
{
    auto& mem = revkit::core::Memory::get();
    std::string result;
    result.reserve(64);
    for (uint32_t i = 0; i < k_max_name_len; ++i)
    {
        auto ch = mem.read_val<char>(addr + i);
        if (!ch || *ch == '\0')
            break;
        result += *ch;
    }
    return result;
}

}

inline std::optional<PeInfo> read_pe_info(uintptr_t base)
{
    auto& mem = revkit::core::Memory::get();

    auto dos_sig = mem.read_val<uint16_t>(base);
    if (!dos_sig || *dos_sig != IMAGE_DOS_SIGNATURE)
        return std::nullopt;

    auto e_lfanew = mem.read_val<int32_t>(base + offsetof(IMAGE_DOS_HEADER, e_lfanew));
    if (!e_lfanew)
        return std::nullopt;

    uintptr_t nt_addr = base + static_cast<uint32_t>(*e_lfanew);

    auto nt_sig = mem.read_val<uint32_t>(nt_addr);
    if (!nt_sig || *nt_sig != IMAGE_NT_SIGNATURE)
        return std::nullopt;

    uintptr_t file_hdr_addr = nt_addr + offsetof(IMAGE_NT_HEADERS64, FileHeader);
    auto machine = mem.read_val<uint16_t>(file_hdr_addr + offsetof(IMAGE_FILE_HEADER, Machine));
    auto num_sections = mem.read_val<uint16_t>(file_hdr_addr + offsetof(IMAGE_FILE_HEADER, NumberOfSections));
    auto opt_hdr_size = mem.read_val<uint16_t>(file_hdr_addr + offsetof(IMAGE_FILE_HEADER, SizeOfOptionalHeader));

    if (!machine || !num_sections || !opt_hdr_size)
        return std::nullopt;

    bool is64 = (*machine == IMAGE_FILE_MACHINE_AMD64 || *machine == IMAGE_FILE_MACHINE_IA64);

    PeInfo info{};
    info.machine  = *machine;
    info.is_64bit = is64;
    info.image_base = base;

    uintptr_t opt_addr = nt_addr + offsetof(IMAGE_NT_HEADERS64, OptionalHeader);

    if (is64)
    {
        auto magic        = mem.read_val<uint16_t>(opt_addr + offsetof(IMAGE_OPTIONAL_HEADER64, Magic));
        auto ep_rva       = mem.read_val<uint32_t>(opt_addr + offsetof(IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint));
        auto image_base64 = mem.read_val<uint64_t>(opt_addr + offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase));
        auto image_size   = mem.read_val<uint32_t>(opt_addr + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage));

        if (!magic || !ep_rva || !image_base64 || !image_size)
            return std::nullopt;

        info.ep_rva        = *ep_rva;
        info.preferred_base = static_cast<uintptr_t>(*image_base64);
        info.image_size    = *image_size;
    }
    else
    {
        auto magic        = mem.read_val<uint16_t>(opt_addr + offsetof(IMAGE_OPTIONAL_HEADER32, Magic));
        auto ep_rva       = mem.read_val<uint32_t>(opt_addr + offsetof(IMAGE_OPTIONAL_HEADER32, AddressOfEntryPoint));
        auto image_base32 = mem.read_val<uint32_t>(opt_addr + offsetof(IMAGE_OPTIONAL_HEADER32, ImageBase));
        auto image_size   = mem.read_val<uint32_t>(opt_addr + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage));

        if (!magic || !ep_rva || !image_base32 || !image_size)
            return std::nullopt;

        info.ep_rva        = *ep_rva;
        info.preferred_base = static_cast<uintptr_t>(*image_base32);
        info.image_size    = *image_size;
    }

    info.ep_va = base + info.ep_rva;

    uintptr_t sec_addr = nt_addr
                         + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
                         + *opt_hdr_size;

    uint32_t safe_count = std::min(static_cast<uint32_t>(*num_sections),
                                   static_cast<uint32_t>(detail::k_max_sections));

    for (uint32_t i = 0; i < safe_count; ++i)
    {
        uintptr_t s = sec_addr + i * sizeof(IMAGE_SECTION_HEADER);

        IMAGE_SECTION_HEADER raw{};
        if (!mem.read(s, &raw, sizeof(raw)))
            break;

        PeSection sec{};
        std::memcpy(sec.name, raw.Name, IMAGE_SIZEOF_SHORT_NAME);
        sec.name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
        sec.rva             = raw.VirtualAddress;
        sec.vsize           = raw.Misc.VirtualSize;
        sec.raw_off         = raw.PointerToRawData;
        sec.raw_size        = raw.SizeOfRawData;
        sec.characteristics = raw.Characteristics;

        info.sections.push_back(sec);
    }

    return info;
}

inline std::vector<PeExport> read_exports(uintptr_t base)
{
    auto& mem = revkit::core::Memory::get();
    std::vector<PeExport> result;

    auto dos_sig = mem.read_val<uint16_t>(base);
    if (!dos_sig || *dos_sig != IMAGE_DOS_SIGNATURE)
        return result;

    auto e_lfanew = mem.read_val<int32_t>(base + offsetof(IMAGE_DOS_HEADER, e_lfanew));
    if (!e_lfanew)
        return result;

    uintptr_t nt_addr = base + static_cast<uint32_t>(*e_lfanew);

    auto nt_sig = mem.read_val<uint32_t>(nt_addr);
    if (!nt_sig || *nt_sig != IMAGE_NT_SIGNATURE)
        return result;

    uintptr_t file_hdr_addr = nt_addr + offsetof(IMAGE_NT_HEADERS64, FileHeader);
    auto machine = mem.read_val<uint16_t>(file_hdr_addr + offsetof(IMAGE_FILE_HEADER, Machine));
    if (!machine)
        return result;

    bool is64 = (*machine == IMAGE_FILE_MACHINE_AMD64 || *machine == IMAGE_FILE_MACHINE_IA64);

    IMAGE_DATA_DIRECTORY export_dir = detail::get_data_dir(base, is64, nt_addr, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (export_dir.VirtualAddress == 0 || export_dir.Size == 0)
        return result;

    uintptr_t exp_addr = base + export_dir.VirtualAddress;
    uint32_t  exp_end  = export_dir.VirtualAddress + export_dir.Size;

    auto num_funcs  = mem.read_val<uint32_t>(exp_addr + offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfFunctions));
    auto num_names  = mem.read_val<uint32_t>(exp_addr + offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfNames));
    auto base_ord   = mem.read_val<uint32_t>(exp_addr + offsetof(IMAGE_EXPORT_DIRECTORY, Base));
    auto rva_funcs  = mem.read_val<uint32_t>(exp_addr + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfFunctions));
    auto rva_names  = mem.read_val<uint32_t>(exp_addr + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNames));
    auto rva_ords   = mem.read_val<uint32_t>(exp_addr + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals));

    if (!num_funcs || !base_ord || !rva_funcs)
        return result;

    uint32_t safe_funcs = std::min(*num_funcs, static_cast<uint32_t>(detail::k_max_exports));
    uint32_t safe_names = num_names ? std::min(*num_names, static_cast<uint32_t>(detail::k_max_exports)) : 0u;

    std::unordered_map<uint32_t, std::string> ord_to_name;

    if (safe_names > 0 && rva_names && rva_ords)
    {
        uintptr_t names_tbl = base + *rva_names;
        uintptr_t ords_tbl  = base + *rva_ords;

        for (uint32_t i = 0; i < safe_names; ++i)
        {
            auto name_rva = mem.read_val<uint32_t>(names_tbl + i * sizeof(uint32_t));
            auto ord_idx  = mem.read_val<uint16_t>(ords_tbl  + i * sizeof(uint16_t));
            if (!name_rva || !ord_idx)
                continue;
            std::string fn = detail::read_cstr(base + *name_rva);
            ord_to_name[*ord_idx] = fn;
        }
    }

    uintptr_t func_tbl = base + *rva_funcs;

    for (uint32_t i = 0; i < safe_funcs; ++i)
    {
        auto fn_rva = mem.read_val<uint32_t>(func_tbl + i * sizeof(uint32_t));
        if (!fn_rva || *fn_rva == 0)
            continue;

        if (*fn_rva >= export_dir.VirtualAddress && *fn_rva < exp_end)
            continue;

        PeExport exp{};
        exp.ordinal = *base_ord + i;
        exp.rva     = *fn_rva;
        exp.va      = base + *fn_rva;

        auto it = ord_to_name.find(i);
        if (it != ord_to_name.end())
            exp.name = it->second;

        result.push_back(std::move(exp));
    }

    std::sort(result.begin(), result.end(), [](const PeExport& a, const PeExport& b)
    {
        return a.ordinal < b.ordinal;
    });

    return result;
}

inline std::vector<PeImportDll> read_imports(uintptr_t base)
{
    auto& mem = revkit::core::Memory::get();
    std::vector<PeImportDll> result;

    auto dos_sig = mem.read_val<uint16_t>(base);
    if (!dos_sig || *dos_sig != IMAGE_DOS_SIGNATURE)
        return result;

    auto e_lfanew = mem.read_val<int32_t>(base + offsetof(IMAGE_DOS_HEADER, e_lfanew));
    if (!e_lfanew)
        return result;

    uintptr_t nt_addr = base + static_cast<uint32_t>(*e_lfanew);

    auto nt_sig = mem.read_val<uint32_t>(nt_addr);
    if (!nt_sig || *nt_sig != IMAGE_NT_SIGNATURE)
        return result;

    uintptr_t file_hdr_addr = nt_addr + offsetof(IMAGE_NT_HEADERS64, FileHeader);
    auto machine = mem.read_val<uint16_t>(file_hdr_addr + offsetof(IMAGE_FILE_HEADER, Machine));
    if (!machine)
        return result;

    bool is64 = (*machine == IMAGE_FILE_MACHINE_AMD64 || *machine == IMAGE_FILE_MACHINE_IA64);

    IMAGE_DATA_DIRECTORY import_dir = detail::get_data_dir(base, is64, nt_addr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (import_dir.VirtualAddress == 0)
        return result;

    uintptr_t desc_addr = base + import_dir.VirtualAddress;

    for (uint32_t d = 0; d < detail::k_max_import_dlls; ++d)
    {
        uintptr_t cur_desc = desc_addr + d * sizeof(IMAGE_IMPORT_DESCRIPTOR);

        auto name_rva       = mem.read_val<uint32_t>(cur_desc + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name));
        auto original_first = mem.read_val<uint32_t>(cur_desc + offsetof(IMAGE_IMPORT_DESCRIPTOR, OriginalFirstThunk));
        auto first_thunk    = mem.read_val<uint32_t>(cur_desc + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk));

        if (!name_rva || *name_rva == 0)
            break;

        PeImportDll dll{};
        dll.name = detail::read_cstr(base + *name_rva);

        uint32_t thunk_rva = (original_first && *original_first != 0) ? *original_first : (first_thunk ? *first_thunk : 0u);

        if (thunk_rva != 0)
        {
            uintptr_t thunk_addr = base + thunk_rva;

            for (uint32_t f = 0; f < detail::k_max_import_funcs; ++f)
            {
                if (is64)
                {
                    auto thunk_val = mem.read_val<uint64_t>(thunk_addr + f * sizeof(uint64_t));
                    if (!thunk_val || *thunk_val == 0)
                        break;

                    if (*thunk_val & detail::k_image_ordinal_flag64)
                    {
                        uint64_t ord = *thunk_val & 0xFFFFull;
                        dll.functions.push_back("#" + std::to_string(ord));
                    }
                    else
                    {
                        uint32_t hint_rva = static_cast<uint32_t>(*thunk_val & 0xFFFFFFFFull);
                        std::string fn = detail::read_cstr(base + hint_rva + sizeof(uint16_t));
                        dll.functions.push_back(std::move(fn));
                    }
                }
                else
                {
                    auto thunk_val = mem.read_val<uint32_t>(thunk_addr + f * sizeof(uint32_t));
                    if (!thunk_val || *thunk_val == 0)
                        break;

                    if (*thunk_val & detail::k_image_ordinal_flag32)
                    {
                        uint32_t ord = *thunk_val & 0xFFFFu;
                        dll.functions.push_back("#" + std::to_string(ord));
                    }
                    else
                    {
                        uint32_t hint_rva = *thunk_val & 0x7FFFFFFFu;
                        std::string fn = detail::read_cstr(base + hint_rva + sizeof(uint16_t));
                        dll.functions.push_back(std::move(fn));
                    }
                }
            }
        }

        result.push_back(std::move(dll));
    }

    return result;
}

inline std::optional<PeSection> find_section(uintptr_t base, const std::string& name)
{
    auto info = read_pe_info(base);
    if (!info)
        return std::nullopt;

    for (const auto& sec : info->sections)
    {
        if (std::string(sec.name) == name)
            return sec;
    }
    return std::nullopt;
}

}
