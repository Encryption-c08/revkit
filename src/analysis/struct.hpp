#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <sstream>
#include <iomanip>
#include "../core/memory.hpp"
#include "../util/encoding.hpp"

namespace revkit::analysis
{

struct StructField
{
    std::string name;
    uintptr_t  offset;
    std::string type;
    size_t     length = 0;
    size_t     count  = 1;
};

struct StructValue
{
    std::string name;
    uintptr_t  offset;
    std::string type;
    std::string value;
};

namespace detail
{

inline size_t field_elem_size(const std::string& type)
{
    if (type == "u8"  || type == "i8"  || type == "bool") return 1;
    if (type == "u16" || type == "i16") return 2;
    if (type == "u32" || type == "i32" || type == "f32") return 4;
    if (type == "u64" || type == "i64" || type == "f64" || type == "ptr") return 8;
    if (type == "vec2") return 8;
    if (type == "vec3") return 12;
    return 0;
}

inline std::string read_number(const std::string& type, uintptr_t at)
{
    auto& mem = revkit::core::Memory::get();
    if (type == "u8")  { auto x = mem.read_val<uint8_t>(at);  return x ? std::to_string(*x) : "?"; }
    if (type == "i8")  { auto x = mem.read_val<int8_t>(at);   return x ? std::to_string((int)*x) : "?"; }
    if (type == "u16") { auto x = mem.read_val<uint16_t>(at); return x ? std::to_string(*x) : "?"; }
    if (type == "i16") { auto x = mem.read_val<int16_t>(at);  return x ? std::to_string((int)*x) : "?"; }
    if (type == "u32") { auto x = mem.read_val<uint32_t>(at); return x ? std::to_string(*x) : "?"; }
    if (type == "i32") { auto x = mem.read_val<int32_t>(at);  return x ? std::to_string(*x) : "?"; }
    if (type == "u64") { auto x = mem.read_val<uint64_t>(at); return x ? std::to_string(*x) : "?"; }
    if (type == "i64") { auto x = mem.read_val<int64_t>(at);  return x ? std::to_string(*x) : "?"; }
    if (type == "f32") { auto x = mem.read_val<float>(at);    return x ? std::to_string(*x) : "?"; }
    if (type == "f64") { auto x = mem.read_val<double>(at);   return x ? std::to_string(*x) : "?"; }
    if (type == "ptr") { auto x = mem.read_val<uintptr_t>(at); return x ? revkit::util::addr_str(*x) : "?"; }
    if (type == "bool"){ auto x = mem.read_val<uint8_t>(at);  return x ? (*x ? "true" : "false") : "?"; }
    return "?";
}

inline std::string read_vec(const std::string& type, uintptr_t at)
{
    auto& mem = revkit::core::Memory::get();
    int n = (type == "vec3") ? 3 : 2;
    std::string s;
    for (int i = 0; i < n; ++i)
    {
        auto x = mem.read_val<float>(at + i * 4);
        if (i) s += ", ";
        s += x ? std::to_string(*x) : "?";
    }
    return "(" + s + ")";
}

inline std::string read_str(uintptr_t at, size_t length)
{
    auto& mem = revkit::core::Memory::get();
    size_t n = length ? length : 64;
    auto buf = mem.read_bytes(at, n);
    std::string s;
    for (auto b : buf)
    {
        if (b == 0) break;
        if (b < 0x20 || b > 0x7E) break;
        s += (char)b;
    }
    return s;
}

inline std::string read_utf16(uintptr_t at, size_t length)
{
    auto& mem = revkit::core::Memory::get();
    size_t n = length ? length : 32;
    auto buf = mem.read_bytes(at, n * 2);
    std::string s;
    for (size_t i = 0; i + 1 < buf.size(); i += 2)
    {
        uint16_t c = (uint16_t)buf[i] | ((uint16_t)buf[i + 1] << 8);
        if (c == 0) break;
        if (c > 0x7E) { s += '?'; continue; }
        s += (char)c;
    }
    return s;
}

}

inline std::vector<StructValue> read_struct(uintptr_t base,
                                            const std::vector<StructField>& fields)
{
    std::vector<StructValue> out;
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return out;

    for (const auto& f : fields)
    {
        size_t elem = detail::field_elem_size(f.type);
        size_t count = f.count ? f.count : 1;

        if (f.type == "str" || f.type == "utf16")
        {
            StructValue v;
            v.name   = f.name;
            v.offset = f.offset;
            v.type   = f.type;
            v.value  = (f.type == "str")
                        ? detail::read_str(base + f.offset, f.length)
                        : detail::read_utf16(base + f.offset, f.length);
            out.push_back(std::move(v));
            continue;
        }
        if (f.type == "vec2" || f.type == "vec3")
        {
            StructValue v;
            v.name   = f.name;
            v.offset = f.offset;
            v.type   = f.type;
            v.value  = detail::read_vec(f.type, base + f.offset);
            out.push_back(std::move(v));
            continue;
        }

        for (size_t i = 0; i < count; ++i)
        {
            StructValue v;
            v.name   = (count > 1) ? f.name + "[" + std::to_string(i) + "]" : f.name;
            v.offset = f.offset + i * elem;
            v.type   = f.type;
            v.value  = detail::read_number(f.type, base + v.offset);
            out.push_back(std::move(v));
        }
    }

    return out;
}

}
