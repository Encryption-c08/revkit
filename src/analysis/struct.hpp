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

inline bool write_number(const std::string& type, uintptr_t at, const std::string& value)
{
    auto& mem = revkit::core::Memory::get();
    try
    {
        if (type == "u8"  || type == "bool") { uint8_t  v = (uint8_t)std::stoul(value);        return mem.write(at, &v, 1); }
        if (type == "i8")                     { int8_t   v = (int8_t)std::stoi(value);         return mem.write(at, &v, 1); }
        if (type == "u16")                    { uint16_t v = (uint16_t)std::stoul(value);      return mem.write(at, &v, 2); }
        if (type == "i16")                    { int16_t  v = (int16_t)std::stoi(value);        return mem.write(at, &v, 2); }
        if (type == "u32")                    { uint32_t v = (uint32_t)std::stoul(value);      return mem.write(at, &v, 4); }
        if (type == "i32")                    { int32_t  v = (int32_t)std::stoi(value);        return mem.write(at, &v, 4); }
        if (type == "u64" || type == "ptr")   { uint64_t v = (uint64_t)std::stoull(value, nullptr, 0); return mem.write(at, &v, 8); }
        if (type == "i64")                    { int64_t  v = (int64_t)std::stoll(value);       return mem.write(at, &v, 8); }
        if (type == "f32")                    { float    v = std::stof(value);                 return mem.write(at, &v, 4); }
        if (type == "f64")                    { double   v = std::stod(value);                 return mem.write(at, &v, 8); }
    }
    catch (...) { return false; }
    return false;
}

inline bool write_vec(const std::string& type, uintptr_t at, const std::string& value)
{
    auto& mem = revkit::core::Memory::get();
    float comp[3] = { 0, 0, 0 };
    int n = (type == "vec3") ? 3 : 2;
    size_t idx = 0;
    std::string tok;
    for (char c : value)
    {
        if (c == ',' || c == ' ' || c == '(' || c == ')')
        {
            if (!tok.empty() && idx < 3)
            {
                try { comp[idx++] = std::stof(tok); } catch (...) {}
                tok.clear();
            }
        }
        else tok += c;
    }
    if (!tok.empty() && idx < 3)
    {
        try { comp[idx++] = std::stof(tok); } catch (...) {}
    }
    return mem.write(at, comp, (size_t)n * sizeof(float));
}

inline bool write_str(uintptr_t at, size_t length, const std::string& value, bool utf16)
{
    auto& mem = revkit::core::Memory::get();
    if (utf16)
    {
        size_t n = length ? length : value.size();
        std::vector<uint8_t> buf((n + 1) * 2, 0);
        for (size_t i = 0; i < value.size() && i < n; ++i)
        {
            uint16_t c = (uint16_t)(unsigned char)value[i];
            buf[i * 2]     = (uint8_t)(c & 0xFF);
            buf[i * 2 + 1] = (uint8_t)(c >> 8);
        }
        return mem.write(at, buf.data(), (n + 1) * 2);
    }
    size_t n = length ? length : value.size();
    std::vector<uint8_t> buf(n + 1, 0);
    for (size_t i = 0; i < value.size() && i < n; ++i)
        buf[i] = (uint8_t)value[i];
    return mem.write(at, buf.data(), n + 1);
}

inline size_t write_struct(uintptr_t base,
                           const std::vector<StructField>& fields,
                           const std::vector<std::string>& values)
{
    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return 0;

    size_t written = 0;
    size_t vi = 0;
    for (const auto& f : fields)
    {
        size_t elem = detail::field_elem_size(f.type);
        size_t count = f.count ? f.count : 1;

        if (f.type == "str" || f.type == "utf16")
        {
            if (vi < values.size() && write_str(base + f.offset, f.length, values[vi], f.type == "utf16"))
                ++written;
            ++vi;
            continue;
        }
        if (f.type == "vec2" || f.type == "vec3")
        {
            if (vi < values.size() && write_vec(f.type, base + f.offset, values[vi]))
                ++written;
            ++vi;
            continue;
        }

        for (size_t i = 0; i < count; ++i)
        {
            if (vi >= values.size()) break;
            if (write_number(f.type, base + f.offset + i * elem, values[vi]))
                ++written;
            ++vi;
        }
    }
    return written;
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
