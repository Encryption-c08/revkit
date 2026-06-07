#include "kdmapper_dll.hpp"
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

namespace revkit::driver
{

std::wstring KdMapper::get_exe_dir()
{
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    PathRemoveFileSpecW(buf);
    return std::wstring(buf) + L"\\";
}

bool KdMapper::is_available()
{
    std::wstring dir = get_exe_dir();
    bool has_dll = GetFileAttributesW((dir + L"kdmapper.dll").c_str()) != INVALID_FILE_ATTRIBUTES;
    bool has_exe = GetFileAttributesW((dir + L"kdmapper.exe").c_str()) != INVALID_FILE_ATTRIBUTES;
    return has_dll || has_exe;
}

HMODULE KdMapper::try_load_dll()
{
    std::wstring path = get_exe_dir() + L"kdmapper.dll";
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
        return nullptr;
    return LoadLibraryW(path.c_str());
}

bool KdMapper::run_exe_fallback(const std::wstring& driver_path)
{
    std::wstring exe = get_exe_dir() + L"kdmapper.exe";
    if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES)
        return false;

    std::wstring cmd = L"\"" + exe + L"\" \"" + driver_path + L"\"";

    STARTUPINFOW si{};
    si.cb       = sizeof(si);
    si.dwFlags  = STARTF_USESTDHANDLES;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);

    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr,
                        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;

    WaitForSingleObject(pi.hProcess, 15000);

    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return exit_code == 0;
}

bool KdMapper::map_driver(const std::wstring& driver_path)
{
    HMODULE hmod = try_load_dll();

    if (hmod)
    {
        using MapDriverFn = bool (__stdcall*)(const wchar_t*);
        auto fn = reinterpret_cast<MapDriverFn>(GetProcAddress(hmod, "MapDriver"));

        if (fn)
        {
            bool result = fn(driver_path.c_str());
            FreeLibrary(hmod);
            return result;
        }

        FreeLibrary(hmod);
    }

    return run_exe_fallback(driver_path);
}

}
