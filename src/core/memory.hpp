#pragma once

#include "../driver/backend.hpp"
#include <Windows.h>
#include <vector>
#include <optional>
#include <cstdint>

namespace revkit::core
{

struct Region
{
    uintptr_t base;
    size_t    size;
    DWORD     protect;
    DWORD     type;
    DWORD     state;
};

class Memory
{
public:
    static Memory& get()
    {
        static Memory instance;
        return instance;
    }

    Memory(const Memory&)            = delete;
    Memory& operator=(const Memory&) = delete;

    bool try_use_driver()
    {
        if (revkit::driver::DriverMemory::get().is_open())
        {
            use_driver_ = true;
            return true;
        }
        if (revkit::driver::DriverMemory::get().open())
        {
            use_driver_ = true;
            return true;
        }
        return false;
    }

    bool using_driver() const { return use_driver_; }

    bool attach(uint32_t pid)
    {
        detach();
        if (use_driver_)
        {
            if (revkit::driver::DriverMemory::get().attach(pid))
            {
                pid_ = pid;
                handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                return true;
            }
        }
        handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!handle_) return false;
        pid_ = pid;
        return true;
    }

    void detach()
    {
        if (use_driver_)
        {
            revkit::driver::DriverMemory::get().detach();
        }
        if (handle_)
        {
            CloseHandle(handle_);
            handle_ = nullptr;
        }
        pid_ = 0;
    }

    bool     is_attached() const { return handle_ != nullptr || pid_ != 0; }
    uint32_t pid()         const { return pid_; }

    bool read(uintptr_t addr, void* out, size_t size)
    {
        if (use_driver_ && revkit::driver::DriverMemory::get().is_attached())
        {
            return revkit::driver::DriverMemory::get().read(addr, out, size);
        }
        if (!handle_) return false;
        SIZE_T transferred = 0;
        return ReadProcessMemory(handle_,
                                 reinterpret_cast<LPCVOID>(addr),
                                 out, size, &transferred)
               && transferred == size;
    }

    bool write(uintptr_t addr, const void* data, size_t sz)
    {
        if (!handle_)
            return false;
        if (use_driver_)
        {
            return revkit::driver::DriverMemory::get().write(addr, data, sz);
        }
        SIZE_T transferred = 0;
        return WriteProcessMemory(handle_,
                                  reinterpret_cast<LPVOID>(addr),
                                  data, sz, &transferred)
               && transferred == sz;
    }

    template<typename T>
    std::optional<T> read_val(uintptr_t addr)
    {
        T v{};
        if (!read(addr, &v, sizeof(T)))
            return std::nullopt;
        return v;
    }

    std::vector<uint8_t> read_bytes(uintptr_t addr, size_t size)
    {
        std::vector<uint8_t> buf(size);
        if (!read(addr, buf.data(), size))
            buf.clear();
        return buf;
    }

    std::vector<uint8_t> read_safe(uintptr_t addr, size_t size,
                                   size_t chunk = 0x1000)
    {
        std::vector<uint8_t> out;
        out.reserve(size);
        size_t done = 0;
        while (done < size)
        {
            size_t batch = (size - done < chunk) ? size - done : chunk;
            std::vector<uint8_t> tmp(batch);
            if (!read(addr + done, tmp.data(), batch))
                break;
            out.insert(out.end(), tmp.begin(), tmp.end());
            done += batch;
        }
        return out;
    }

    std::optional<Region> query(uintptr_t addr)
    {
        if (!handle_)
            return std::nullopt;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(handle_,
                            reinterpret_cast<LPCVOID>(addr),
                            &mbi, sizeof(mbi)))
            return std::nullopt;
        Region r{};
        r.base    = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        r.size    = mbi.RegionSize;
        r.protect = mbi.Protect;
        r.type    = mbi.Type;
        r.state   = mbi.State;
        return r;
    }

    std::vector<Region> regions()
    {
        std::vector<Region> out;
        if (!handle_)
            return out;
        uintptr_t addr = 0;
        MEMORY_BASIC_INFORMATION mbi{};
        while (VirtualQueryEx(handle_,
                              reinterpret_cast<LPCVOID>(addr),
                              &mbi, sizeof(mbi)))
        {
            Region r{};
            r.base    = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            r.size    = mbi.RegionSize;
            r.protect = mbi.Protect;
            r.type    = mbi.Type;
            r.state   = mbi.State;
            out.push_back(r);
            uintptr_t next = r.base + r.size;
            if (next <= addr)
                break;
            addr = next;
        }
        return out;
    }

private:
    Memory() = default;
    ~Memory() { detach(); }

    HANDLE   handle_     = nullptr;
    uint32_t pid_        = 0;
    bool     use_driver_ = false;
};

}
