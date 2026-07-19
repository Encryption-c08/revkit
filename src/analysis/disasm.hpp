#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include "../core/memory.hpp"
#include "../util/encoding.hpp"

namespace revkit::analysis
{

struct Instruction
{
    uintptr_t   address;
    uint8_t     length;
    std::string bytes_hex;
    std::string mnemonic;
};

namespace detail
{

static constexpr uint8_t k_rex_mask    = 0xF0;
static constexpr uint8_t k_rex_base    = 0x40;
static constexpr uint8_t k_rex_w       = 0x08;
static constexpr uint8_t k_mod_mask    = 0xC0;
static constexpr uint8_t k_mod_disp8   = 0x40;
static constexpr uint8_t k_mod_disp32  = 0x80;
static constexpr uint8_t k_mod_reg     = 0xC0;
static constexpr uint8_t k_rm_mask     = 0x07;
static constexpr uint8_t k_rm_sib      = 0x04;
static constexpr uint8_t k_rm_disp32   = 0x05;
static constexpr uint8_t k_sib_base5   = 0x05;

static constexpr const char* k_reg8[]  = {"al","cl","dl","bl","ah","ch","dh","bh",
                                           "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
static constexpr const char* k_reg16[] = {"ax","cx","dx","bx","sp","bp","si","di",
                                           "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
static constexpr const char* k_reg32[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi",
                                           "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
static constexpr const char* k_reg64[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                           "r8","r9","r10","r11","r12","r13","r14","r15"};

inline std::string bytes_to_hex(const uint8_t* p, uint8_t n)
{
    std::string out;
    for (uint8_t i = 0; i < n; ++i)
    {
        if (i) out += ' ';
        out += "0123456789ABCDEF"[(p[i] >> 4) & 0xF];
        out += "0123456789ABCDEF"[p[i] & 0xF];
    }
    return out;
}

inline std::string hex32(uint32_t v)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << v;
    return ss.str();
}

inline std::string hex64(uint64_t v)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << v;
    return ss.str();
}

static constexpr const char* k_xmm[] = {
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15"
};
static constexpr const char* k_ymm[] = {
    "ymm0","ymm1","ymm2","ymm3","ymm4","ymm5","ymm6","ymm7",
    "ymm8","ymm9","ymm10","ymm11","ymm12","ymm13","ymm14","ymm15"
};
static constexpr const char* k_zmm[] = {
    "zmm0","zmm1","zmm2","zmm3","zmm4","zmm5","zmm6","zmm7",
    "zmm8","zmm9","zmm10","zmm11","zmm12","zmm13","zmm14","zmm15"
};

struct DecodeCtx
{
    const uint8_t* buf;
    size_t         cap;
    size_t         pos;
    bool           x64;
    bool           rex_w;
    bool           rex_r;
    bool           rex_x;
    bool           rex_b;
    uint8_t        opr_sz;
    uint8_t        addr_sz;
    bool           pfx_66;
    bool           pfx_f2;
    bool           pfx_f3;
    bool           vex;
    bool           evex;
    uint8_t        vex_map;
    uint8_t        vex_vvvv;
    uint8_t        vex_l;
    uint8_t        vex_pp;
    uint8_t        vex_aaa;
    bool           vex_z;
};

inline bool peek(const DecodeCtx& c, uint8_t& out)
{
    if (c.pos >= c.cap) return false;
    out = c.buf[c.pos];
    return true;
}

inline bool consume(DecodeCtx& c, uint8_t& out)
{
    if (c.pos >= c.cap) return false;
    out = c.buf[c.pos++];
    return true;
}

inline bool consume_u16(DecodeCtx& c, uint16_t& out)
{
    if (c.pos + 1 >= c.cap) return false;
    out = static_cast<uint16_t>(c.buf[c.pos]) | (static_cast<uint16_t>(c.buf[c.pos+1]) << 8);
    c.pos += 2;
    return true;
}

inline bool consume_u32(DecodeCtx& c, uint32_t& out)
{
    if (c.pos + 3 >= c.cap) return false;
    out = static_cast<uint32_t>(c.buf[c.pos])
        | (static_cast<uint32_t>(c.buf[c.pos+1]) << 8)
        | (static_cast<uint32_t>(c.buf[c.pos+2]) << 16)
        | (static_cast<uint32_t>(c.buf[c.pos+3]) << 24);
    c.pos += 4;
    return true;
}

inline bool consume_u64(DecodeCtx& c, uint64_t& out)
{
    if (c.pos + 7 >= c.cap) return false;
    out = 0;
    for (int i = 0; i < 8; ++i)
        out |= static_cast<uint64_t>(c.buf[c.pos + i]) << (i * 8);
    c.pos += 8;
    return true;
}

inline std::string decode_modrm_rm(DecodeCtx& c, uint8_t modrm, uintptr_t instr_va)
{
    uint8_t mod  = (modrm & k_mod_mask) >> 6;
    uint8_t rm   = (modrm & k_rm_mask);
    uint8_t real_rm = rm | (c.rex_b ? 8 : 0);

    if (mod == 3)
    {
        if (c.opr_sz == 8) return k_reg64[real_rm];
        if (c.opr_sz == 4) return k_reg32[real_rm];
        if (c.opr_sz == 2) return k_reg16[real_rm];
        return k_reg8[real_rm];
    }

    std::string mem = "[";
    bool has_sib  = (rm == k_rm_sib) && (c.addr_sz == 8 || c.addr_sz == 4);
    bool rip_rel  = (c.x64 && rm == k_rm_disp32 && mod == 0);

    if (rip_rel)
    {
        uint32_t disp = 0;
        consume_u32(c, disp);
        uintptr_t target = instr_va + c.pos + static_cast<int32_t>(disp);
        mem += "rip+" + hex64(target);
        mem += "]";
        return mem;
    }

    uint8_t sib_byte = 0;
    if (has_sib)
    {
        consume(c, sib_byte);
    }

    if (has_sib)
    {
        uint8_t scale = 1 << ((sib_byte >> 6) & 0x3);
        uint8_t idx   = ((sib_byte >> 3) & 0x7) | (c.rex_x ? 8 : 0);
        uint8_t base  = (sib_byte & 0x7) | (c.rex_b ? 8 : 0);
        bool    no_base = (base == k_sib_base5 && mod == 0);
        if (!no_base) mem += k_reg64[base];
        if (idx != 4)
        {
            if (!no_base) mem += "+";
            mem += k_reg64[idx];
            if (scale > 1) mem += "*" + std::to_string(scale);
        }
        if (mod == k_mod_disp8 >> 6)
        {
            uint8_t d8 = 0; consume(c, d8);
            if (d8) { mem += "+"; mem += hex32(d8); }
        }
        else if (mod == k_mod_disp32 >> 6 || no_base)
        {
            uint32_t d32 = 0; consume_u32(c, d32);
            if (d32) { mem += "+"; mem += hex32(d32); }
        }
    }
    else
    {
        mem += k_reg64[real_rm];
        if (mod == (k_mod_disp8 >> 6))
        {
            uint8_t d8 = 0; consume(c, d8);
            if (d8) { mem += "+"; mem += hex32(d8); }
        }
        else if (mod == (k_mod_disp32 >> 6))
        {
            uint32_t d32 = 0; consume_u32(c, d32);
            if (d32) { mem += "+"; mem += hex32(d32); }
        }
    }
    mem += "]";
    return mem;
}

inline std::string reg_from_modrm_reg(const DecodeCtx& c, uint8_t modrm)
{
    uint8_t reg = ((modrm >> 3) & 0x7) | (c.rex_r ? 8 : 0);
    if (c.opr_sz == 8) return k_reg64[reg];
    if (c.opr_sz == 4) return k_reg32[reg];
    if (c.opr_sz == 2) return k_reg16[reg];
    return k_reg8[reg];
}

inline const char* vx_reg(uint8_t idx, int sz)
{
    if (sz <= 0) return k_xmm[idx & 15];
    if (sz == 1) return k_ymm[idx & 15];
    return k_zmm[idx & 15];
}

inline int vex_size(const DecodeCtx& c)
{
    if (c.evex && c.vex_l >= 2) return 2;
    if (c.vex_l == 1)            return 1;
    return 0;
}

inline std::string decode_vex(DecodeCtx& c, uint8_t op, uintptr_t va)
{
    int sz = vex_size(c);

    auto vx_reg_from_modrm = [&](uint8_t modrm) -> std::string
    {
        uint8_t r = ((modrm >> 3) & 7) | (c.rex_r ? 8 : 0);
        return vx_reg(r, sz);
    };
    auto vx_rm = [&](uint8_t modrm) -> std::string
    {
        uint8_t rm = (modrm & 7) | (c.rex_b ? 8 : 0);
        return vx_reg(rm, sz);
    };
    auto memop = [&](uint8_t modrm) -> std::string
    {
        uint8_t saved = c.opr_sz; c.opr_sz = 8;
        std::string s = decode_modrm_rm(c, modrm, va);
        c.opr_sz = saved;
        return s;
    };
    auto mask = [&]() -> std::string
    {
        std::string m;
        if (c.evex)
        {
            if (c.vex_aaa) m += " {k" + std::to_string(c.vex_aaa) + "}";
            if (c.vex_z)   m += "{z}";
        }
        return m;
    };
    auto load = [&](const char* name) -> std::string
    {
        uint8_t modrm = 0; if (!consume(c, modrm)) return std::string(name) + " ??";
        std::string dst = vx_reg_from_modrm(modrm);
        uint8_t  md  = (modrm >> 6) & 3;
        std::string src = (md == 3) ? vx_rm(modrm) : memop(modrm);
        return std::string(name) + " " + dst + ", " + src + mask();
    };
    auto store = [&](const char* name) -> std::string
    {
        uint8_t modrm = 0; if (!consume(c, modrm)) return std::string(name) + " ??";
        uint8_t  md  = (modrm >> 6) & 3;
        std::string dst = (md == 3) ? vx_rm(modrm) : memop(modrm);
        std::string src = vx_reg_from_modrm(modrm);
        return std::string(name) + " " + dst + ", " + src + mask();
    };
    auto tri = [&](const char* name) -> std::string
    {
        uint8_t modrm = 0; if (!consume(c, modrm)) return std::string(name) + " ??";
        std::string dst = vx_reg_from_modrm(modrm);
        std::string s1  = vx_reg(c.vex_vvvv, sz);
        uint8_t  md  = (modrm >> 6) & 3;
        std::string s2 = (md == 3) ? vx_rm(modrm) : memop(modrm);
        return std::string(name) + " " + dst + ", " + s1 + ", " + s2 + mask();
    };
    auto tri_imm = [&](const char* name) -> std::string
    {
        uint8_t modrm = 0; if (!consume(c, modrm)) return std::string(name) + " ??";
        std::string dst = vx_reg_from_modrm(modrm);
        std::string s1  = vx_reg(c.vex_vvvv, sz);
        uint8_t  md  = (modrm >> 6) & 3;
        std::string s2 = (md == 3) ? vx_rm(modrm) : memop(modrm);
        uint8_t  imm = 0; consume(c, imm);
        return std::string(name) + " " + dst + ", " + s1 + ", " + s2 + ", " + hex32(imm) + mask();
    };
    auto extract = [&](const char* name) -> std::string
    {
        uint8_t modrm = 0; if (!consume(c, modrm)) return std::string(name) + " ??";
        uint8_t  md  = (modrm >> 6) & 3;
        std::string dst = (md == 3) ? k_reg32[(modrm & 7) | (c.rex_b ? 8 : 0)] : memop(modrm);
        std::string src = vx_reg_from_modrm(modrm);
        uint8_t  imm = 0; consume(c, imm);
        return std::string(name) + " " + dst + ", " + src + ", " + hex32(imm) + mask();
    };
    auto insert = [&](const char* name) -> std::string
    {
        uint8_t modrm = 0; if (!consume(c, modrm)) return std::string(name) + " ??";
        std::string dst = vx_reg_from_modrm(modrm);
        uint8_t  md  = (modrm >> 6) & 3;
        std::string s1  = (md == 3) ? k_reg32[(modrm & 7) | (c.rex_b ? 8 : 0)] : memop(modrm);
        std::string s2  = vx_reg(c.vex_vvvv, sz);
        uint8_t  imm = 0; consume(c, imm);
        return std::string(name) + " " + dst + ", " + s1 + ", " + s2 + ", " + hex32(imm) + mask();
    };
    auto ppname = [&](const char* np, const char* p66,
                      const char* pf3, const char* pf2) -> const char*
    {
        if (c.vex_pp == 3) return pf2;
        if (c.vex_pp == 2) return pf3;
        if (c.vex_pp == 1) return p66;
        return np;
    };
    auto fma = [&](const char* base) -> std::string
    {
        const char* suf = ppname("ps", "pd", "ss", "sd");
        uint8_t modrm = 0; if (!consume(c, modrm)) return std::string(base) + " ??";
        std::string dst = vx_reg_from_modrm(modrm);
        std::string s1  = vx_reg(c.vex_vvvv, sz);
        uint8_t  md  = (modrm >> 6) & 3;
        std::string s2 = (md == 3) ? vx_rm(modrm) : memop(modrm);
        return std::string(base) + suf + " " + dst + ", " + s1 + ", " + s2 + mask();
    };

    if (c.vex_map == 1)
    {
        switch (op)
        {
        case 0x10: return load(ppname("vmovups","vmovupd","vmovss","vmovsd"));
        case 0x11: return store(ppname("vmovups","vmovupd","vmovss","vmovsd"));
        case 0x28: return load(ppname("vmovaps","vmovapd","vmovaps","vmovaps"));
        case 0x29: return store(ppname("vmovaps","vmovapd","vmovaps","vmovaps"));
        case 0x2B: return store(ppname("vmovntps","vmovntpd","vmovntps","vmovntps"));
        case 0x51: return load(ppname("vsqrtps","vsqrtpd","vsqrtss","vsqrtsd"));
        case 0x52: return load(ppname("vrcpps","vrcpps","vrcpss","vrcpss"));
        case 0x53: return load(ppname("vrcpps","vrcpps","vrcpss","vrcpss"));
        case 0x54: return tri(ppname("vandps","vandpd","vandps","vandps"));
        case 0x55: return tri(ppname("vandnps","vandnpd","vandnps","vandnps"));
        case 0x56: return tri(ppname("vorps","vorpd","vorps","vorps"));
        case 0x57: return tri(ppname("vxorps","vxorpd","vxorps","vxorps"));
        case 0x58: return tri(ppname("vaddps","vaddpd","vaddss","vaddsd"));
        case 0x59: return tri(ppname("vmulps","vmulpd","vmulss","vmulsd"));
        case 0x5A: return load(ppname("vcvtps2pd","vcvtpd2ps","vcvtss2sd","vcvtsd2ss"));
        case 0x5B: return load(ppname("vcvtps2dq","vcvtpd2dq","vcvttps2dq","vcvtpd2dq"));
        case 0x5C: return tri(ppname("vsubps","vsubpd","vsubss","vsubsd"));
        case 0x5D: return tri(ppname("vminps","vminpd","vminss","vminsd"));
        case 0x5E: return tri(ppname("vdivps","vdivpd","vdivss","vdivsd"));
        case 0x5F: return tri(ppname("vmaxps","vmaxpd","vmaxss","vmaxsd"));
        case 0x60: return tri("vpunpcklbw");
        case 0x61: return tri("vpunpcklwd");
        case 0x62: return tri("vpunpckldq");
        case 0x63: return tri("vpacksswb");
        case 0x64: return tri("vpcmpgtb");
        case 0x65: return tri("vpcmpgtw");
        case 0x66: return tri("vpcmpgtd");
        case 0x67: return tri("vpackuswb");
        case 0x68: return tri("vpunpckhbw");
        case 0x69: return tri("vpunpckhwd");
        case 0x6A: return tri("vpunpckhdq");
        case 0x6B: return tri("vpackssdw");
        case 0x6E: return load("vmovd");
        case 0x6F: return load(ppname("vmovdqa","vmovdqu","vmovdqa","vmovdqu"));
        case 0x70: return tri_imm(ppname("vpshufd","vpshufd","vpshuflw","vpshufhw"));
        case 0x74: return tri("vpcmpeqb");
        case 0x75: return tri("vpcmpeqw");
        case 0x76: return tri("vpcmpeqd");
        case 0x7C: return tri(ppname("vhaddps","vhaddpd","vhaddps","vhaddps"));
        case 0x7D: return tri(ppname("vhsubps","vhsubpd","vhsubps","vhsubps"));
        case 0x7E: return load("vmovq");
        case 0x7F: return store(ppname("vmovdqa","vmovdqu","vmovdqa","vmovdqu"));
        case 0xC2: return tri_imm(ppname("vcmpps","vcmppd","vcmpss","vcmpsd"));
        case 0xC6: return tri_imm(ppname("vshufps","vshufpd","vshufps","vshufps"));
        case 0xDB: return tri("vpand");
        case 0xEB: return tri("vpor");
        case 0xEF: return tri("vpxor");
        case 0xFC: return tri("vpaddb");
        case 0xFD: return tri("vpaddw");
        case 0xFE: return tri("vpaddd");
        case 0xF8: return tri("vpsubb");
        case 0xF9: return tri("vpsubw");
        case 0xFA: return tri("vpsubd");
        case 0xFB: return tri("vpsubq");
        default:   return std::string("v??? 0F ") + hex32(op);
        }
    }
    else if (c.vex_map == 2)
    {
        switch (op)
        {
        case 0x00: return tri("vpshufb");
        case 0x01: return tri("vphaddw");
        case 0x02: return tri("vphaddd");
        case 0x03: return tri("vphaddsw");
        case 0x04: return tri("vpmaddubsw");
        case 0x05: return tri("vphsubw");
        case 0x06: return tri("vphsubd");
        case 0x07: return tri("vphsubsw");
        case 0x08: return tri("vpsignb");
        case 0x09: return tri("vpsignw");
        case 0x0A: return tri("vpsignd");
        case 0x0B: return tri("vpmulhrsw");
        case 0x17: return load(ppname("vptest","vptest","vptest","vptest"));
        case 0x1C: return load("vpabsb");
        case 0x1D: return load("vpabsw");
        case 0x1E: return load("vpabsd");
        case 0x20: return load("vpmovsxbw");
        case 0x21: return load("vpmovsxbd");
        case 0x22: return load("vpmovsxbq");
        case 0x23: return load("vpmovsxwd");
        case 0x24: return load("vpmovsxwq");
        case 0x25: return load("vpmovsxdq");
        case 0x30: return load("vpmovzxbw");
        case 0x31: return load("vpmovzxbd");
        case 0x32: return load("vpmovzxbq");
        case 0x33: return load("vpmovzxwd");
        case 0x34: return load("vpmovzxwq");
        case 0x35: return load("vpmovzxdq");
        case 0x28: return tri("vpmuldq");
        case 0x29: return tri("vpmuludq");
        case 0x2B: return tri("vpackusdw");
        case 0x36: return tri(ppname("vpermd","vpermd","vpermd","vpermd"));
        case 0x37: return tri(ppname("vpermq","vpermq","vpermq","vpermq"));
        case 0x58: return load("vpbroadcastd");
        case 0x59: return load(ppname("vbroadcastss","vbroadcastss","vbroadcastss","vbroadcastss"));
        case 0x5A: return load(ppname("vbroadcastsd","vbroadcastsd","vbroadcastsd","vbroadcastsd"));
        case 0x5B: return load(ppname("vbroadcastf128","vbroadcastf128","vbroadcastf128","vbroadcastf128"));
        case 0x78: return load("vpbroadcastb");
        case 0x79: return load("vpbroadcastw");
        case 0x96: return fma("vfmsub132");
        case 0x97: return fma("vfmsub213");
        case 0x98: return fma("vfmadd132");
        case 0x99: return fma("vfmadd213");
        case 0x9A: return fma("vfmadd231");
        case 0x9B: return fma("vfmsub231");
        case 0x9C: return fma("vfnmadd132");
        case 0x9D: return fma("vfnmadd213");
        case 0x9E: return fma("vfnmadd231");
        default:   return std::string("v??? 0F38 ") + hex32(op);
        }
    }
    else if (c.vex_map == 3)
    {
        switch (op)
        {
        case 0x0C: return tri_imm(ppname("vblendps","vblendps","vblendps","vblendps"));
        case 0x0D: return tri_imm(ppname("vblendpd","vblendpd","vblendpd","vblendpd"));
        case 0x0E: return tri_imm(ppname("vblendvps","vblendvps","vblendvps","vblendvps"));
        case 0x0F: return tri_imm(ppname("vblendvpd","vblendvpd","vblendvpd","vblendvpd"));
        case 0x14: return extract("vpextrb");
        case 0x15: return extract("vpextrw");
        case 0x16: return extract("vpextrd");
        case 0x20: return insert("vpinsrb");
        case 0x21: return insert("vpinsrd");
        case 0x22: return insert("vpinsrq");
        case 0x40: return tri_imm(ppname("vdpps","vdpps","vdpps","vdpps"));
        case 0x41: return tri_imm(ppname("vdppd","vdppd","vdppd","vdppd"));
        case 0x44: return tri_imm(ppname("vpclmulqdq","vpclmulqdq","vpclmulqdq","vpclmulqdq"));
        case 0x46: return tri_imm(ppname("vperm2i128","vperm2i128","vperm2i128","vperm2i128"));
        default:   return std::string("v??? 0F3A ") + hex32(op);
        }
    }

    return std::string("v??? map") + hex32(c.vex_map) + " " + hex32(op);
}

inline Instruction decode_one(const uint8_t* buf, size_t cap, uintptr_t va, bool x64)
{
    Instruction ins{};
    ins.address = va;

    DecodeCtx c{};
    c.buf    = buf;
    c.cap    = cap;
    c.pos    = 0;
    c.x64    = x64;
    c.rex_w  = false;
    c.rex_r  = false;
    c.rex_x  = false;
    c.rex_b  = false;
    c.opr_sz = x64 ? 4 : 4;
    c.addr_sz = x64 ? 8 : 4;
    c.pfx_66 = false;
    c.pfx_f2 = false;
    c.pfx_f3 = false;
    c.vex     = false;
    c.evex    = false;
    c.vex_map = 0;
    c.vex_vvvv = 0;
    c.vex_l   = 0;
    c.vex_pp  = 0;
    c.vex_aaa = 0;
    c.vex_z   = false;

    if (cap == 0)
    {
        ins.length   = 1;
        ins.mnemonic = "??";
        ins.bytes_hex = "??";
        return ins;
    }

    uint8_t b = 0;

    while (c.pos < cap)
    {
        if (!consume(c, b)) break;

        if (b == 0x66) { c.opr_sz = 2; c.pfx_66 = true; continue; }
        if (b == 0x67) { c.addr_sz = x64 ? 4 : 2; continue; }
        if (b == 0xF0) continue;
        if (b == 0xF2) { c.pfx_f2 = true; continue; }
        if (b == 0xF3) { c.pfx_f3 = true; continue; }
        if (b == 0x2E || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65 || b == 0x36) continue;

        if (x64 && (b & k_rex_mask) == k_rex_base)
        {
            c.rex_w = (b & k_rex_w) != 0;
            c.rex_r = (b & 0x04) != 0;
            c.rex_x = (b & 0x02) != 0;
            c.rex_b = (b & 0x01) != 0;
            if (c.rex_w) c.opr_sz = 8;
            continue;
        }

        if (x64 && b == 0xC4)
        {
            uint8_t v1 = 0, v2 = 0;
            if (!consume(c, v1) || !consume(c, v2))
            {
                ins.length = (uint8_t)c.pos;
                ins.bytes_hex = bytes_to_hex(buf, ins.length);
                ins.mnemonic = "??";
                return ins;
            }
            c.rex_r  = ((v1 >> 7) & 1) ? 0 : 1;
            c.rex_x  = ((v1 >> 6) & 1) ? 0 : 1;
            c.rex_b  = ((v1 >> 5) & 1) ? 0 : 1;
            c.vex_map = v1 & 0x1F;
            c.rex_w  = (v2 >> 7) & 1;
            c.vex_vvvv = (v2 >> 3) & 0xF;
            c.vex_l  = (v2 >> 2) & 1;
            c.vex_pp = v2 & 0x3;
            c.vex    = true;
            continue;
        }
        if (x64 && b == 0xC5)
        {
            uint8_t v1 = 0;
            if (!consume(c, v1))
            {
                ins.length = (uint8_t)c.pos;
                ins.bytes_hex = bytes_to_hex(buf, ins.length);
                ins.mnemonic = "??";
                return ins;
            }
            c.rex_r  = ((v1 >> 7) & 1) ? 0 : 1;
            c.vex_map = 1;
            c.rex_w  = 0;
            c.vex_vvvv = (v1 >> 3) & 0xF;
            c.vex_l  = (v1 >> 2) & 1;
            c.vex_pp = v1 & 0x3;
            c.vex    = true;
            continue;
        }
        if (x64 && b == 0x62)
        {
            uint8_t p0 = 0, p1 = 0, p2 = 0;
            if (!consume(c, p0) || !consume(c, p1) || !consume(c, p2))
            {
                ins.length = (uint8_t)c.pos;
                ins.bytes_hex = bytes_to_hex(buf, ins.length);
                ins.mnemonic = "??";
                return ins;
            }
            c.rex_r  = ((p0 >> 7) & 1) ? 0 : 1;
            c.rex_x  = ((p0 >> 6) & 1) ? 0 : 1;
            c.rex_b  = ((p0 >> 5) & 1) ? 0 : 1;
            c.rex_w  = (p1 >> 7) & 1;
            c.vex_map = p0 & 0x1F;
            c.vex_vvvv = ((p1 >> 3) & 0xF) | (((p0 >> 4) & 1) << 4);
            c.vex_l  = ((p2 >> 6) & 1) << 1 | ((p2 >> 5) & 1);
            c.vex_aaa = p2 & 0x7;
            c.vex_z  = (p2 >> 7) & 1;
            c.vex_pp = (c.pfx_66 ? 1 : 0) | (c.pfx_f2 ? 3 : 0) | (c.pfx_f3 ? 2 : 0);
            c.evex   = true;
            c.vex    = true;
            continue;
        }

        break;
    }

    uint8_t op = b;
    std::string mnem;

    auto emit_rm_reg = [&](const std::string& name, bool rm_dest) -> std::string
    {
        uint8_t modrm = 0;
        if (!consume(c, modrm)) return name + " ??";
        std::string rm  = decode_modrm_rm(c, modrm, va);
        std::string reg = reg_from_modrm_reg(c, modrm);
        if (rm_dest) return name + " " + rm  + ", " + reg;
        else         return name + " " + reg + ", " + rm;
    };

    auto emit_rm_imm = [&](const std::string& name) -> std::string
    {
        uint8_t modrm = 0;
        if (!consume(c, modrm)) return name + " ??";
        std::string rm = decode_modrm_rm(c, modrm, va);
        uint32_t imm = 0;
        if (c.opr_sz == 2)
        {
            uint16_t i16 = 0; consume_u16(c, i16); imm = i16;
        }
        else
        {
            consume_u32(c, imm);
        }
        return name + " " + rm + ", " + hex32(imm);
    };

    auto emit_rm_imm8 = [&](const std::string& name) -> std::string
    {
        uint8_t modrm = 0;
        if (!consume(c, modrm)) return name + " ??";
        std::string rm = decode_modrm_rm(c, modrm, va);
        uint8_t imm = 0; consume(c, imm);
        return name + " " + rm + ", " + hex32(imm);
    };

    auto jcc_name = [](uint8_t cc) -> const char*
    {
        static const char* names[] = {
            "jo","jno","jb","jae","je","jne","jbe","ja",
            "js","jns","jp","jnp","jl","jge","jle","jg"
        };
        return (cc < 16) ? names[cc] : "jcc";
    };

    if (c.vex)
    {
        uint8_t op2 = 0;
        if (!consume(c, op2))
            mnem = "??";
        else
            mnem = detail::decode_vex(c, op2, va);
    }
    else switch (op)
    {
        case 0x00: mnem = emit_rm_reg("add", true);  break;
        case 0x01: mnem = emit_rm_reg("add", true);  break;
        case 0x02: mnem = emit_rm_reg("add", false); break;
        case 0x03: mnem = emit_rm_reg("add", false); break;
        case 0x08: mnem = emit_rm_reg("or",  true);  break;
        case 0x09: mnem = emit_rm_reg("or",  true);  break;
        case 0x0A: mnem = emit_rm_reg("or",  false); break;
        case 0x0B: mnem = emit_rm_reg("or",  false); break;
        case 0x20: mnem = emit_rm_reg("and", true);  break;
        case 0x21: mnem = emit_rm_reg("and", true);  break;
        case 0x22: mnem = emit_rm_reg("and", false); break;
        case 0x23: mnem = emit_rm_reg("and", false); break;
        case 0x28: mnem = emit_rm_reg("sub", true);  break;
        case 0x29: mnem = emit_rm_reg("sub", true);  break;
        case 0x2A: mnem = emit_rm_reg("sub", false); break;
        case 0x2B: mnem = emit_rm_reg("sub", false); break;
        case 0x30: mnem = emit_rm_reg("xor", true);  break;
        case 0x31: mnem = emit_rm_reg("xor", true);  break;
        case 0x32: mnem = emit_rm_reg("xor", false); break;
        case 0x33: mnem = emit_rm_reg("xor", false); break;
        case 0x38: mnem = emit_rm_reg("cmp", true);  break;
        case 0x39: mnem = emit_rm_reg("cmp", true);  break;
        case 0x3A: mnem = emit_rm_reg("cmp", false); break;
        case 0x3B: mnem = emit_rm_reg("cmp", false); break;
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
        {
            uint8_t reg = (op & 7) | (c.rex_b ? 8 : 0);
            mnem = "push " + std::string(k_reg64[reg]);
            break;
        }
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        {
            uint8_t reg = (op & 7) | (c.rex_b ? 8 : 0);
            mnem = "pop " + std::string(k_reg64[reg]);
            break;
        }
        case 0x63: mnem = emit_rm_reg("movsxd", false); break;
        case 0x68:
        {
            uint32_t imm = 0; consume_u32(c, imm);
            mnem = "push " + hex32(imm);
            break;
        }
        case 0x6A:
        {
            uint8_t imm = 0; consume(c, imm);
            mnem = "push " + hex32(imm);
            break;
        }
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        {
            uint8_t rel8 = 0; consume(c, rel8);
            uintptr_t target = va + c.pos + static_cast<int8_t>(rel8);
            mnem = std::string(jcc_name(op & 0xF)) + " " + hex64(target);
            break;
        }
        case 0x80: mnem = emit_rm_imm8("add/sub/cmp"); break;
        case 0x81: mnem = emit_rm_imm("add/sub/cmp");  break;
        case 0x83: mnem = emit_rm_imm8("add/sub/cmp"); break;
        case 0x84: mnem = emit_rm_reg("test", true);  break;
        case 0x85: mnem = emit_rm_reg("test", true);  break;
        case 0x86: mnem = emit_rm_reg("xchg", true);  break;
        case 0x87: mnem = emit_rm_reg("xchg", true);  break;
        case 0x88: mnem = emit_rm_reg("mov",  true);  break;
        case 0x89: mnem = emit_rm_reg("mov",  true);  break;
        case 0x8A: mnem = emit_rm_reg("mov",  false); break;
        case 0x8B: mnem = emit_rm_reg("mov",  false); break;
        case 0x8D: mnem = emit_rm_reg("lea",  false); break;
        case 0x90: mnem = "nop"; break;
        case 0x98: mnem = c.rex_w ? "cdqe" : "cwde"; break;
        case 0x99: mnem = c.rex_w ? "cqo"  : "cdq";  break;
        case 0xA4: mnem = "movsb"; break;
        case 0xA5: mnem = c.rex_w ? "movsq" : "movsd"; break;
        case 0xAA: mnem = "stosb"; break;
        case 0xAB: mnem = c.rex_w ? "stosq" : "stosd"; break;
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        {
            uint8_t reg = (op & 7) | (c.rex_b ? 8 : 0);
            uint8_t imm = 0; consume(c, imm);
            mnem = "mov " + std::string(k_reg8[reg]) + ", " + hex32(imm);
            break;
        }
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        {
            uint8_t reg = (op & 7) | (c.rex_b ? 8 : 0);
            if (c.rex_w)
            {
                uint64_t imm = 0; consume_u64(c, imm);
                mnem = "mov " + std::string(k_reg64[reg]) + ", " + hex64(imm);
            }
            else if (c.opr_sz == 2)
            {
                uint16_t imm = 0; consume_u16(c, imm);
                mnem = "mov " + std::string(k_reg16[reg]) + ", " + hex32(imm);
            }
            else
            {
                uint32_t imm = 0; consume_u32(c, imm);
                mnem = "mov " + std::string(k_reg32[reg]) + ", " + hex32(imm);
            }
            break;
        }
        case 0xC0: case 0xC1:
        {
            uint8_t modrm = 0; consume(c, modrm);
            std::string rm = decode_modrm_rm(c, modrm, va);
            uint8_t grp = (modrm >> 3) & 7;
            static const char* shift_names[] = {"rol","ror","rcl","rcr","shl","shr","sal","sar"};
            uint8_t cnt = 0; consume(c, cnt);
            mnem = std::string(shift_names[grp]) + " " + rm + ", " + hex32(cnt);
            break;
        }
        case 0xC2: { uint16_t imm = 0; consume_u16(c, imm); mnem = "ret " + hex32(imm); break; }
        case 0xC3: mnem = "ret"; break;
        case 0xC6: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); uint8_t i = 0; consume(c, i); mnem = "mov byte ptr ..., " + hex32(i); break; }
        case 0xC7: { uint8_t modrm = 0; consume(c, modrm); std::string rm = decode_modrm_rm(c, modrm, va); uint32_t i = 0; consume_u32(c, i); mnem = "mov " + rm + ", " + hex32(i); break; }
        case 0xC9: mnem = "leave"; break;
        case 0xCC: mnem = "int3"; break;
        case 0xCD: { uint8_t i = 0; consume(c, i); mnem = "int " + hex32(i); break; }
        case 0xCF: mnem = "iret"; break;
        case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        {
            uint8_t modrm = 0; consume(c, modrm);
            std::string rm = decode_modrm_rm(c, modrm, va);
            uint8_t grp = (modrm >> 3) & 7;
            static const char* shift_names[] = {"rol","ror","rcl","rcr","shl","shr","sal","sar"};
            mnem = std::string(shift_names[grp]) + " " + rm + ((op & 2) ? ", cl" : ", 1");
            break;
        }
        case 0xE2: { uint8_t rel8 = 0; consume(c, rel8); uintptr_t t = va + c.pos + static_cast<int8_t>(rel8); mnem = "loop " + hex64(t); break; }
        case 0xE8: { uint32_t rel = 0; consume_u32(c, rel); uintptr_t t = va + c.pos + static_cast<int32_t>(rel); mnem = "call " + hex64(t); break; }
        case 0xE9: { uint32_t rel = 0; consume_u32(c, rel); uintptr_t t = va + c.pos + static_cast<int32_t>(rel); mnem = "jmp "  + hex64(t); break; }
        case 0xEB: { uint8_t rel8 = 0; consume(c, rel8); uintptr_t t = va + c.pos + static_cast<int8_t>(rel8); mnem = "jmp " + hex64(t); break; }
        case 0xF4: mnem = "hlt"; break;
        case 0xF6: { uint8_t modrm = 0; consume(c, modrm); std::string rm = decode_modrm_rm(c, modrm, va); uint8_t grp = (modrm >> 3) & 7; if (grp == 0) { uint8_t i = 0; consume(c, i); mnem = "test " + rm + ", " + hex32(i); } else { static const char* g[] = {"test","test","not","neg","mul","imul","div","idiv"}; mnem = std::string(g[grp]) + " " + rm; } break; }
        case 0xF7: { uint8_t modrm = 0; consume(c, modrm); std::string rm = decode_modrm_rm(c, modrm, va); uint8_t grp = (modrm >> 3) & 7; if (grp == 0) { emit_rm_imm("test"); mnem = "test " + rm + ", imm"; } else { static const char* g[] = {"test","test","not","neg","mul","imul","div","idiv"}; mnem = std::string(g[grp]) + " " + rm; } break; }
        case 0xF8: mnem = "clc"; break;
        case 0xF9: mnem = "stc"; break;
        case 0xFD: mnem = "std"; break;
        case 0xFE: { uint8_t modrm = 0; consume(c, modrm); std::string rm = decode_modrm_rm(c, modrm, va); uint8_t grp = (modrm >> 3) & 7; mnem = (grp == 0 ? "inc " : "dec ") + rm; break; }
        case 0xFF:
        {
            uint8_t modrm = 0; consume(c, modrm);
            std::string rm = decode_modrm_rm(c, modrm, va);
            uint8_t grp = (modrm >> 3) & 7;
            static const char* g[] = {"inc","dec","call","callf","jmp","jmpf","push","??"};
            mnem = std::string(g[grp]) + " " + rm;
            break;
        }
        case 0x0F:
        {
            uint8_t op2 = 0;
            if (!consume(c, op2)) { mnem = "??"; break; }

            auto sse_name = [&](const char* np, const char* p66,
                                const char* pf3, const char* pf2) -> const char*
            {
                if (c.pfx_f2) return pf2;
                if (c.pfx_f3) return pf3;
                if (c.pfx_66) return p66;
                return np;
            };

            auto xmm_reg = [&](uint8_t modrm) -> std::string
            {
                uint8_t r = ((modrm >> 3) & 7) | (c.rex_r ? 8 : 0);
                return k_xmm[r & 15];
            };

            auto sse_load = [&](const char* name) -> std::string
            {
                uint8_t modrm = 0;
                if (!consume(c, modrm)) return std::string(name) + " ??";
                std::string reg = xmm_reg(modrm);
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm  = modrm & 7;
                if (mod == 3)
                {
                    uint8_t r2 = rm | (c.rex_b ? 8 : 0);
                    return std::string(name) + " " + reg + ", " + k_xmm[r2 & 15];
                }
                uint8_t saved = c.opr_sz; c.opr_sz = 8;
                std::string mem = decode_modrm_rm(c, modrm, va);
                c.opr_sz = saved;
                return std::string(name) + " " + reg + ", " + mem;
            };

            auto sse_store = [&](const char* name) -> std::string
            {
                uint8_t modrm = 0;
                if (!consume(c, modrm)) return std::string(name) + " ??";
                std::string reg = xmm_reg(modrm);
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm  = modrm & 7;
                if (mod == 3)
                {
                    uint8_t r2 = rm | (c.rex_b ? 8 : 0);
                    return std::string(name) + " " + k_xmm[r2 & 15] + ", " + reg;
                }
                uint8_t saved = c.opr_sz; c.opr_sz = 8;
                std::string mem = decode_modrm_rm(c, modrm, va);
                c.opr_sz = saved;
                return std::string(name) + " " + mem + ", " + reg;
            };

            auto sse_arith = [&](const char* name) -> std::string
            {
                return sse_load(name);
            };

            auto gpr_reg = [&](uint8_t modrm) -> std::string
            {
                uint8_t r = ((modrm >> 3) & 7) | (c.rex_r ? 8 : 0);
                return c.rex_w ? k_reg64[r] : k_reg32[r];
            };

            switch (op2)
            {

            case 0x80: case 0x81: case 0x82: case 0x83:
            case 0x84: case 0x85: case 0x86: case 0x87:
            case 0x88: case 0x89: case 0x8A: case 0x8B:
            case 0x8C: case 0x8D: case 0x8E: case 0x8F:
            {
                uint32_t rel = 0; consume_u32(c, rel);
                uintptr_t t = va + c.pos + static_cast<int32_t>(rel);
                mnem = std::string(jcc_name(op2 & 0xF)) + " " + hex64(t);
                break;
            }

            case 0x10: mnem = sse_load(sse_name("movups","movupd","movss","movsd")); break;
            case 0x11: mnem = sse_store(sse_name("movups","movupd","movss","movsd")); break;
            case 0x12: mnem = sse_load(sse_name("movlps","movlpd","movsldup","movddup")); break;
            case 0x13: mnem = sse_store(sse_name("movlps","movlpd","??","??")); break;
            case 0x16: mnem = sse_load(sse_name("movhps","movhpd","movshdup","??")); break;
            case 0x17: mnem = sse_store(sse_name("movhps","movhpd","??","??")); break;
            case 0x28: mnem = sse_load(sse_name("movaps","movapd","??","??")); break;
            case 0x29: mnem = sse_store(sse_name("movaps","movapd","??","??")); break;
            case 0x2A:
            {
                uint8_t modrm = 0; consume(c, modrm);
                std::string dst = xmm_reg(modrm);
                uint8_t saved = c.opr_sz; c.opr_sz = 8;
                std::string src = decode_modrm_rm(c, modrm, va);
                c.opr_sz = saved;
                const char* n = sse_name("cvtpi2ps","cvtpi2pd","cvtsi2ss","cvtsi2sd");
                mnem = std::string(n) + " " + dst + ", " + src;
                break;
            }
            case 0x2B: mnem = sse_store(sse_name("movntps","movntpd","??","??")); break;
            case 0x2C:
            {
                uint8_t modrm = 0; consume(c, modrm);
                std::string dst = (c.pfx_f2 || c.pfx_f3) ? gpr_reg(modrm) : xmm_reg(modrm);
                uint8_t saved = c.opr_sz; c.opr_sz = 8;
                std::string src = ((modrm >> 6) == 3)
                    ? k_xmm[(modrm & 7) | (c.rex_b ? 8 : 0)]
                    : decode_modrm_rm(c, modrm, va);
                c.opr_sz = saved;
                const char* n = sse_name("cvttps2pi","cvttpd2pi","cvttss2si","cvttsd2si");
                mnem = std::string(n) + " " + dst + ", " + src;
                break;
            }
            case 0x2D:
            {
                uint8_t modrm = 0; consume(c, modrm);
                std::string dst = (c.pfx_f2 || c.pfx_f3) ? gpr_reg(modrm) : xmm_reg(modrm);
                uint8_t saved = c.opr_sz; c.opr_sz = 8;
                std::string src = ((modrm >> 6) == 3)
                    ? k_xmm[(modrm & 7) | (c.rex_b ? 8 : 0)]
                    : decode_modrm_rm(c, modrm, va);
                c.opr_sz = saved;
                const char* n = sse_name("cvtps2pi","cvtpd2pi","cvtss2si","cvtsd2si");
                mnem = std::string(n) + " " + dst + ", " + src;
                break;
            }
            case 0x2E: mnem = sse_arith(c.pfx_66 ? "ucomisd" : "ucomiss"); break;
            case 0x2F: mnem = sse_arith(c.pfx_66 ? "comisd"  : "comiss");  break;

            case 0x51: mnem = sse_arith(sse_name("sqrtps","sqrtpd","sqrtss","sqrtsd")); break;
            case 0x52: mnem = sse_arith(sse_name("rsqrtps","??","rsqrtss","??")); break;
            case 0x53: mnem = sse_arith(sse_name("rcpps","??","rcpss","??")); break;
            case 0x54: mnem = sse_arith(sse_name("andps","andpd","??","??")); break;
            case 0x55: mnem = sse_arith(sse_name("andnps","andnpd","??","??")); break;
            case 0x56: mnem = sse_arith(sse_name("orps","orpd","??","??")); break;
            case 0x57: mnem = sse_arith(sse_name("xorps","xorpd","??","??")); break;
            case 0x58: mnem = sse_arith(sse_name("addps","addpd","addss","addsd")); break;
            case 0x59: mnem = sse_arith(sse_name("mulps","mulpd","mulss","mulsd")); break;
            case 0x5A: mnem = sse_arith(sse_name("cvtps2pd","cvtpd2ps","cvtss2sd","cvtsd2ss")); break;
            case 0x5B: mnem = sse_arith(sse_name("cvtdq2ps","cvtps2dq","cvttps2dq","??")); break;
            case 0x5C: mnem = sse_arith(sse_name("subps","subpd","subss","subsd")); break;
            case 0x5D: mnem = sse_arith(sse_name("minps","minpd","minss","minsd")); break;
            case 0x5E: mnem = sse_arith(sse_name("divps","divpd","divss","divsd")); break;
            case 0x5F: mnem = sse_arith(sse_name("maxps","maxpd","maxss","maxsd")); break;

            case 0x60: mnem = sse_arith("punpcklbw"); break;
            case 0x61: mnem = sse_arith("punpcklwd"); break;
            case 0x62: mnem = sse_arith("punpckldq"); break;
            case 0x63: mnem = sse_arith("packsswb"); break;
            case 0x64: mnem = sse_arith("pcmpgtb"); break;
            case 0x65: mnem = sse_arith("pcmpgtw"); break;
            case 0x66: mnem = sse_arith("pcmpgtd"); break;
            case 0x67: mnem = sse_arith("packuswb"); break;
            case 0x68: mnem = sse_arith("punpckhbw"); break;
            case 0x69: mnem = sse_arith("punpckhwd"); break;
            case 0x6A: mnem = sse_arith("punpckhdq"); break;
            case 0x6B: mnem = sse_arith("packssdw"); break;
            case 0x6C: mnem = sse_arith("punpcklqdq"); break;
            case 0x6D: mnem = sse_arith("punpckhqdq"); break;
            case 0x6E:
            {
                uint8_t modrm = 0; consume(c, modrm);
                std::string dst = xmm_reg(modrm);
                uint8_t saved = c.opr_sz; c.opr_sz = c.rex_w ? 8 : 4;
                std::string src = ((modrm >> 6) == 3)
                    ? (c.rex_w ? k_reg64[(modrm&7)|(c.rex_b?8:0)] : k_reg32[(modrm&7)|(c.rex_b?8:0)])
                    : decode_modrm_rm(c, modrm, va);
                c.opr_sz = saved;
                mnem = std::string(c.rex_w ? "movq " : "movd ") + dst + ", " + src;
                break;
            }
            case 0x6F: mnem = sse_load(sse_name("movq","movdqa","movdqu","??")); break;
            case 0x70:
            {
                uint8_t modrm = 0; consume(c, modrm);
                std::string dst = xmm_reg(modrm);
                uint8_t saved = c.opr_sz; c.opr_sz = 8;
                std::string src = ((modrm >> 6) == 3)
                    ? k_xmm[(modrm&7)|(c.rex_b?8:0)]
                    : decode_modrm_rm(c, modrm, va);
                c.opr_sz = saved;
                uint8_t imm = 0; consume(c, imm);
                const char* n = sse_name("pshufw","pshufd","pshufhw","pshuflw");
                mnem = std::string(n) + " " + dst + ", " + src + ", " + hex32(imm);
                break;
            }
            case 0x74: mnem = sse_arith("pcmpeqb"); break;
            case 0x75: mnem = sse_arith("pcmpeqw"); break;
            case 0x76: mnem = sse_arith("pcmpeqd"); break;
            case 0x7E:
            {
                uint8_t modrm = 0; consume(c, modrm);
                std::string src = xmm_reg(modrm);
                uint8_t saved = c.opr_sz; c.opr_sz = c.rex_w ? 8 : 4;
                std::string dst;
                if ((modrm >> 6) == 3)
                {
                    uint8_t r2 = (modrm&7)|(c.rex_b?8:0);
                    dst = c.rex_w ? k_reg64[r2] : k_reg32[r2];
                }
                else
                {
                    dst = decode_modrm_rm(c, modrm, va);
                }
                c.opr_sz = saved;
                mnem = std::string(c.pfx_f3 ? "movq " : (c.rex_w ? "movq " : "movd "))
                     + dst + ", " + src;
                break;
            }
            case 0x7F: mnem = sse_store(sse_name("movq","movdqa","movdqu","??")); break;

            case 0xC2:
            {
                uint8_t modrm = 0; consume(c, modrm);
                std::string dst = xmm_reg(modrm);
                uint8_t saved = c.opr_sz; c.opr_sz = 8;
                std::string src = ((modrm >> 6) == 3)
                    ? k_xmm[(modrm&7)|(c.rex_b?8:0)]
                    : decode_modrm_rm(c, modrm, va);
                c.opr_sz = saved;
                uint8_t imm = 0; consume(c, imm);
                static const char* cmp[] = {"eq","lt","le","unord","neq","nlt","nle","ord"};
                const char* n = sse_name("cmpps","cmppd","cmpss","cmpsd");
                mnem = std::string(n) + " " + dst + ", " + src + ", " + (imm<8 ? cmp[imm] : hex32(imm));
                break;
            }
            case 0xC4:
            {
                uint8_t modrm = 0; consume(c, modrm);
                std::string dst = xmm_reg(modrm);
                uint8_t saved = c.opr_sz; c.opr_sz = 4;
                std::string src = ((modrm>>6)==3) ? k_reg32[(modrm&7)|(c.rex_b?8:0)] : decode_modrm_rm(c, modrm, va);
                c.opr_sz = saved;
                uint8_t imm = 0; consume(c, imm);
                mnem = "pinsrw " + dst + ", " + src + ", " + hex32(imm);
                break;
            }
            case 0xC5:
            {
                uint8_t modrm = 0; consume(c, modrm);
                uint8_t r2 = (modrm&7)|(c.rex_b?8:0);
                std::string src = k_xmm[r2&15];
                uint8_t imm = 0; consume(c, imm);
                mnem = "pextrw " + gpr_reg(modrm) + ", " + src + ", " + hex32(imm);
                break;
            }
            case 0xC6:
            {
                uint8_t modrm = 0; consume(c, modrm);
                std::string dst = xmm_reg(modrm);
                uint8_t saved = c.opr_sz; c.opr_sz = 8;
                std::string src = ((modrm>>6)==3) ? k_xmm[(modrm&7)|(c.rex_b?8:0)] : decode_modrm_rm(c, modrm, va);
                c.opr_sz = saved;
                uint8_t imm = 0; consume(c, imm);
                mnem = std::string(c.pfx_66 ? "shufpd " : "shufps ") + dst + ", " + src + ", " + hex32(imm);
                break;
            }
            case 0xD0: mnem = sse_arith(c.pfx_66 ? "addsubpd" : "addsubps"); break;
            case 0xD1: mnem = sse_arith("psrlw"); break;
            case 0xD2: mnem = sse_arith("psrld"); break;
            case 0xD3: mnem = sse_arith("psrlq"); break;
            case 0xD4: mnem = sse_arith("paddq"); break;
            case 0xD5: mnem = sse_arith("pmullw"); break;
            case 0xD6: mnem = sse_store("movq"); break;
            case 0xD8: mnem = sse_arith("psubusb"); break;
            case 0xD9: mnem = sse_arith("psubusw"); break;
            case 0xDA: mnem = sse_arith("pminub"); break;
            case 0xDB: mnem = sse_arith("pand"); break;
            case 0xDC: mnem = sse_arith("paddusb"); break;
            case 0xDD: mnem = sse_arith("paddusw"); break;
            case 0xDE: mnem = sse_arith("pmaxub"); break;
            case 0xDF: mnem = sse_arith("pandn"); break;
            case 0xE0: mnem = sse_arith("pavgb"); break;
            case 0xE1: mnem = sse_arith("psraw"); break;
            case 0xE2: mnem = sse_arith("psrad"); break;
            case 0xE3: mnem = sse_arith("pavgw"); break;
            case 0xE4: mnem = sse_arith("pmulhuw"); break;
            case 0xE5: mnem = sse_arith("pmulhw"); break;
            case 0xE6: mnem = sse_arith(sse_name("??","cvttpd2dq","cvtdq2pd","cvtpd2dq")); break;
            case 0xE7: mnem = sse_store(c.pfx_66 ? "movntdq" : "movntq"); break;
            case 0xE8: mnem = sse_arith("psubsb"); break;
            case 0xE9: mnem = sse_arith("psubsw"); break;
            case 0xEA: mnem = sse_arith("pminsw"); break;
            case 0xEB: mnem = sse_arith("por"); break;
            case 0xEC: mnem = sse_arith("paddsb"); break;
            case 0xED: mnem = sse_arith("paddsw"); break;
            case 0xEE: mnem = sse_arith("pmaxsw"); break;
            case 0xEF: mnem = sse_arith(c.pfx_66 ? "pxor" : "pxor"); break;
            case 0xF1: mnem = sse_arith("psllw"); break;
            case 0xF2: mnem = sse_arith("pslld"); break;
            case 0xF3: mnem = sse_arith("psllq"); break;
            case 0xF4: mnem = sse_arith("pmuludq"); break;
            case 0xF5: mnem = sse_arith("pmaddwd"); break;
            case 0xF6: mnem = sse_arith("psadbw"); break;
            case 0xF8: mnem = sse_arith("psubb"); break;
            case 0xF9: mnem = sse_arith("psubw"); break;
            case 0xFA: mnem = sse_arith("psubd"); break;
            case 0xFB: mnem = sse_arith("psubq"); break;
            case 0xFC: mnem = sse_arith("paddb"); break;
            case 0xFD: mnem = sse_arith("paddw"); break;
            case 0xFE: mnem = sse_arith("paddd"); break;

            case 0x1F: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "nop"; break; }
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F:
            {
                static const char* cmov[] = {"cmovo","cmovno","cmovb","cmovae","cmove","cmovne","cmovbe","cmova",
                                             "cmovs","cmovns","cmovp","cmovnp","cmovl","cmovge","cmovle","cmovg"};
                mnem = emit_rm_reg(cmov[op2 & 0xF], false);
                break;
            }
            case 0x90: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "seto ..."; break; }
            case 0x91: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "setno ..."; break; }
            case 0x92: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "setb ..."; break; }
            case 0x93: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "setae ..."; break; }
            case 0x94: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "sete ..."; break; }
            case 0x95: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "setne ..."; break; }
            case 0x96: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "setbe ..."; break; }
            case 0x97: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "seta ..."; break; }
            case 0x98: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "sets ..."; break; }
            case 0x99: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "setns ..."; break; }
            case 0x9A: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "setp ..."; break; }
            case 0x9B: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "setnp ..."; break; }
            case 0x9C: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "setl ..."; break; }
            case 0x9D: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "setge ..."; break; }
            case 0x9E: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "setle ..."; break; }
            case 0x9F: { uint8_t modrm = 0; consume(c, modrm); decode_modrm_rm(c, modrm, va); mnem = "setg ..."; break; }
            case 0xA0: mnem = "push fs"; break;
            case 0xA1: mnem = "pop fs"; break;
            case 0xA2: mnem = "cpuid"; break;
            case 0xA3: mnem = emit_rm_reg("bt", true); break;
            case 0xA4: { mnem = emit_rm_reg("shld", true); uint8_t i=0; consume(c,i); mnem += ", " + hex32(i); break; }
            case 0xA5: mnem = emit_rm_reg("shld", true) + ", cl"; break;
            case 0xA8: mnem = "push gs"; break;
            case 0xA9: mnem = "pop gs"; break;
            case 0xAB: mnem = emit_rm_reg("bts", true); break;
            case 0xAC: { mnem = emit_rm_reg("shrd", true); uint8_t i=0; consume(c,i); mnem += ", " + hex32(i); break; }
            case 0xAD: mnem = emit_rm_reg("shrd", true) + ", cl"; break;
            case 0xAF: mnem = emit_rm_reg("imul", false); break;
            case 0xB0: mnem = emit_rm_reg("cmpxchg", true); break;
            case 0xB1: mnem = emit_rm_reg("cmpxchg", true); break;
            case 0xB3: mnem = emit_rm_reg("btr", true); break;
            case 0xB6: mnem = emit_rm_reg("movzx", false); break;
            case 0xB7: mnem = emit_rm_reg("movzx", false); break;
            case 0xB8: mnem = emit_rm_reg("popcnt", false); break;
            case 0xBA: mnem = emit_rm_imm8("bt/bts/btr/btc"); break;
            case 0xBB: mnem = emit_rm_reg("btc", true); break;
            case 0xBC: mnem = emit_rm_reg("bsf", false); break;
            case 0xBD: mnem = emit_rm_reg("bsr", false); break;
            case 0xBE: mnem = emit_rm_reg("movsx", false); break;
            case 0xBF: mnem = emit_rm_reg("movsx", false); break;
            case 0xC0: mnem = emit_rm_reg("xadd", true); break;
            case 0xC1: mnem = emit_rm_reg("xadd", true); break;
            case 0xC8: case 0xC9: case 0xCA: case 0xCB:
            case 0xCC: case 0xCD: case 0xCE: case 0xCF:
                mnem = "bswap " + std::string(k_reg64[(op2 & 7) | (c.rex_b ? 8 : 0)]);
                break;

            default:
                mnem = "0F " + hex32(op2) + " (unsupported)";
                break;
            }
            break;
        }
        default:
            mnem = "db " + hex32(op);
            break;
    }

    if (c.pos == 0) c.pos = 1;
    if (c.pos > 15) c.pos = 15;

    ins.length    = static_cast<uint8_t>(c.pos);
    ins.bytes_hex = bytes_to_hex(buf, ins.length);
    ins.mnemonic  = mnem;
    return ins;
}

}

inline std::vector<Instruction> disassemble(uintptr_t address, size_t count)
{
    std::vector<Instruction> result;

    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return result;

    static constexpr size_t k_read_size = 15 * 64;
    auto bytes = mem.read_safe(address, k_read_size);
    if (bytes.empty())
        return result;

    bool x64 = true;
    size_t offset = 0;
    for (size_t i = 0; i < count && offset < bytes.size(); ++i)
    {
        size_t remaining = bytes.size() - offset;
        auto ins = detail::decode_one(bytes.data() + offset, remaining,
                                      address + offset, x64);
        if (ins.length == 0) ins.length = 1;
        result.push_back(ins);
        offset += ins.length;
    }

    return result;
}

inline std::vector<Instruction> disassemble_function(uintptr_t address,
                                                     size_t max_insns = 2048)
{
    std::vector<Instruction> result;

    auto& mem = revkit::core::Memory::get();
    if (!mem.is_attached())
        return result;

    bool x64 = true;
    std::vector<uint8_t> buf;
    size_t offset = 0;
    static constexpr size_t k_chunk = 0x10000;

    while (result.size() < max_insns)
    {
        if (offset >= buf.size())
        {
            auto more = mem.read_safe(address + offset, k_chunk);
            if (more.empty()) break;
            buf.insert(buf.end(), more.begin(), more.end());
        }

        size_t remaining = buf.size() - offset;
        auto ins = detail::decode_one(buf.data() + offset, remaining,
                                      address + offset, x64);
        if (ins.length == 0) ins.length = 1;
        result.push_back(ins);

        offset += ins.length;

        const std::string& m = ins.mnemonic;
        if (m == "ret" || m.rfind("ret ", 0) == 0 ||
            m == "int3" || m == "ud2" || m == "iretd" || m == "iret" ||
            m == "??"   || m.rfind("db ", 0) == 0)
            break;
    }

    return result;
}

}
