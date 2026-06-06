#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <optional>
#include <algorithm>
#include <cctype>

namespace revkit::core
{

struct ProcessInfo
{
    uint32_t    pid;
    uint32_t    parent_pid;
    std::string name;
    std::string path;
};

struct ModuleInfo
{
    uintptr_t   base;
    size_t      size;
    std::string name;
    std::string path;
};

namespace detail
{

inline std::string wide_to_utf8(const wchar_t* w)
{
    if (!w || w[0] == L'\0')
        return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1,
                                  nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return {};
    std::string out(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1,
                        out.data(), len, nullptr, nullptr);
    return out;
}

inline std::string process_path(uint32_t pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return {};
    wchar_t buf[MAX_PATH]{};
    DWORD sz = MAX_PATH;
    QueryFullProcessImageNameW(h, 0, buf, &sz);
    CloseHandle(h);
    return wide_to_utf8(buf);
}

}

inline std::vector<ProcessInfo> list_processes()
{
    std::vector<ProcessInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return out;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry))
    {
        do
        {
            ProcessInfo pi{};
            pi.pid        = entry.th32ProcessID;
            pi.parent_pid = entry.th32ParentProcessID;
            pi.name       = detail::wide_to_utf8(entry.szExeFile);
            pi.path       = detail::process_path(entry.th32ProcessID);
            out.push_back(std::move(pi));
        }
        while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return out;
}

inline std::optional<ProcessInfo> find_process(const std::string& name)
{
    auto lower = [](std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        return s;
    };
    std::string target = lower(name);
    for (auto& p : list_processes())
    {
        if (lower(p.name) == target)
            return p;
    }
    return std::nullopt;
}

inline std::optional<ProcessInfo> find_process_by_pid(uint32_t pid)
{
    for (auto& p : list_processes())
    {
        if (p.pid == pid)
            return p;
    }
    return std::nullopt;
}

inline std::vector<ModuleInfo> list_modules(uint32_t pid)
{
    std::vector<ModuleInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return out;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snap, &entry))
    {
        do
        {
            ModuleInfo mi{};
            mi.base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
            mi.size = entry.modBaseSize;
            mi.name = detail::wide_to_utf8(entry.szModule);
            mi.path = detail::wide_to_utf8(entry.szExePath);
            out.push_back(std::move(mi));
        }
        while (Module32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return out;
}

inline std::optional<ModuleInfo> find_module(uint32_t pid,
                                              const std::string& name)
{
    auto lower = [](std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        return s;
    };
    std::string target = lower(name);
    for (auto& m : list_modules(pid))
    {
        if (lower(m.name) == target)
            return m;
    }
    return std::nullopt;
}

}
