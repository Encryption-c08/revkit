#pragma once
#include <string>
#include <cstdint>

namespace revkit::detail
{

// layer 1: position-dependent primary stream
static constexpr uint8_t L1_A = 0x4B;
static constexpr uint8_t L1_B = 0x7F;
static constexpr uint8_t L1_C = 0x21;

// layer 2: secondary stream with different mixing function
static constexpr uint8_t L2_A = 0xA3;
static constexpr uint8_t L2_B = 0x37;
static constexpr uint8_t L2_C = 0x1F;

// layer 3: rotation-based stream
static constexpr uint8_t L3_A = 0xC3;
static constexpr uint8_t L3_B = 0x5E;

// layer 4: CBC-like diffusion IV
static constexpr uint8_t L4_IV = 0xDE;

static constexpr uint8_t key_l1(size_t i)
{
    return static_cast<uint8_t>(L1_A
        ^ static_cast<uint8_t>(L1_B + (i & 0xFF))
        ^ static_cast<uint8_t>(L1_C * ((i | 1u) & 0xFF)));
}

static constexpr uint8_t key_l2(size_t i)
{
    return static_cast<uint8_t>(L2_A
        ^ static_cast<uint8_t>(L2_B + ((i * 3u + 1u) & 0xFF))
        ^ static_cast<uint8_t>(L2_C * ((i ^ 0x55u) & 0xFF)));
}

static constexpr uint8_t key_l3(size_t i)
{
    uint8_t v = static_cast<uint8_t>(i * L3_A + L3_B);
    return static_cast<uint8_t>((v << 3u) | (v >> 5u));
}

template<size_t N>
struct XorStr
{
    uint8_t data[N]{};

    constexpr explicit XorStr(const char (&s)[N])
    {
        uint8_t prev = L4_IV;
        for (size_t i = 0; i < N; ++i)
        {
            uint8_t plain = static_cast<uint8_t>(s[i]);
            // apply 3 independent key streams, then XOR previous plaintext (layer 4)
            data[i] = plain ^ key_l1(i) ^ key_l2(i) ^ key_l3(i) ^ prev;
            prev = plain;
        }
    }

    std::string str() const
    {
        std::string out(N - 1, '\0');
        uint8_t prev = L4_IV;
        for (size_t i = 0; i < N - 1; ++i)
        {
            uint8_t plain = data[i] ^ key_l1(i) ^ key_l2(i) ^ key_l3(i) ^ prev;
            out[i] = static_cast<char>(plain);
            prev = plain;
        }
        return out;
    }

    const char* c_str() const = delete;
};

}

#define XS(literal) ([]() -> std::string { \
    static constexpr auto _xs = ::revkit::detail::XorStr<sizeof(literal)>(literal); \
    return _xs.str(); \
}())
