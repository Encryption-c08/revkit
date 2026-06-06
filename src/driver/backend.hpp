#pragma once
#include "ioctl.hpp"
#include <Windows.h>
#include <vector>
#include <optional>
#include <cstdint>
#include <cstring>

namespace revkit::driver
{

class DriverMemory
{
public:
    static DriverMemory& get()
    {
        static DriverMemory inst;
        return inst;
    }

    DriverMemory(const DriverMemory&)            = delete;
    DriverMemory& operator=(const DriverMemory&) = delete;

    bool open()
    {
        if (is_open()) return true;
        static const char* const k_paths[] = {
            CR_DEVICE_PATH,
            "\\\\.\\RvKit1",
            "\\\\.\\RvKit2",
            "\\\\.\\RvKit3",
            "\\\\.\\RvKit4",
        };
        for (auto path : k_paths)
        {
            device_ = CreateFileA(path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (is_open()) return true;
        }
        return false;
    }

    void close()
    {
        if (is_open()) { CloseHandle(device_); device_ = INVALID_HANDLE_VALUE; }
    }

    bool is_open()     const { return device_ != INVALID_HANDLE_VALUE; }
    bool is_attached() const { return is_open() && pid_ != 0; }

    uint32_t pid()     const { return pid_; }

    bool attach(uint32_t pid)
    {
        if (!is_open()) return false;
        CrAttachIn req{ pid };
        if (!ioctl(CR_IOCTL_ATTACH, &req, sizeof(req), nullptr, 0)) return false;
        pid_ = pid;
        return true;
    }

    bool detach()
    {
        if (!is_open()) return true;
        ioctl(CR_IOCTL_DETACH, nullptr, 0, nullptr, 0);
        pid_ = 0;
        return true;
    }

    bool read(uintptr_t addr, void* out, size_t size)
    {
        if (!is_attached() || !out || size == 0) return false;
        CrReadIn req{ static_cast<uint64_t>(addr), static_cast<uint64_t>(size) };
        DWORD returned = 0;
        return DeviceIoControl(device_, CR_IOCTL_READ,
            &req, sizeof(req),
            out, static_cast<DWORD>(size),
            &returned, nullptr) && returned > 0;
    }

    bool write_physical(uintptr_t addr, const void* data, size_t size)
    {
        if (!is_attached() || !data || size == 0 || size > 4096) return false;
        size_t total = sizeof(CrWritePhysIn) + size;
        std::vector<uint8_t> buf(total);
        CrWritePhysIn hdr{ static_cast<uint64_t>(addr), static_cast<uint64_t>(size) };
        memcpy(buf.data(), &hdr, sizeof(hdr));
        memcpy(buf.data() + sizeof(hdr), data, size);
        DWORD returned = 0;
        return DeviceIoControl(device_, CR_IOCTL_WRITE_PHYSICAL,
            buf.data(), static_cast<DWORD>(total),
            nullptr, 0, &returned, nullptr) != FALSE;
    }

    bool write(uintptr_t addr, const void* data, size_t size)
    {
        if (!is_attached() || !data || size == 0) return false;
        size_t total = sizeof(CrWriteIn) + size;
        std::vector<uint8_t> buf(total);
        CrWriteIn hdr{ static_cast<uint64_t>(addr), static_cast<uint64_t>(size) };
        memcpy(buf.data(), &hdr, sizeof(hdr));
        memcpy(buf.data() + sizeof(hdr), data, size);
        DWORD returned = 0;
        return DeviceIoControl(device_, CR_IOCTL_WRITE,
            buf.data(), static_cast<DWORD>(total),
            nullptr, 0,
            &returned, nullptr) != FALSE;
    }

    struct Region { uintptr_t base; size_t size; uint32_t protect, type, state; };

    std::optional<Region> query(uintptr_t addr)
    {
        if (!is_attached()) return std::nullopt;
        CrQueryIn  in_buf{ static_cast<uint64_t>(addr) };
        CrQueryOut out_buf{};
        DWORD returned = 0;
        if (!DeviceIoControl(device_, CR_IOCTL_QUERY,
                &in_buf, sizeof(in_buf),
                &out_buf, sizeof(out_buf),
                &returned, nullptr))
            return std::nullopt;
        Region r;
        r.base    = static_cast<uintptr_t>(out_buf.base);
        r.size    = static_cast<size_t>(out_buf.size);
        r.protect = out_buf.protect;
        r.type    = out_buf.type;
        r.state   = out_buf.state;
        return r;
    }

private:
    DriverMemory() = default;
    ~DriverMemory() { close(); }

    bool ioctl(DWORD code, void* in_buf, DWORD in_len,
               void* out_buf, DWORD out_len)
    {
        DWORD returned = 0;
        return DeviceIoControl(device_, code,
            in_buf, in_len, out_buf, out_len,
            &returned, nullptr) != FALSE;
    }

    HANDLE   device_ = INVALID_HANDLE_VALUE;
    uint32_t pid_    = 0;
};

}
