#include <windows.h>
#include <shlwapi.h>
#include <string>
#pragma comment(lib, "shlwapi.lib")

static std::wstring get_dir()
{
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    PathRemoveFileSpecW(buf);
    return std::wstring(buf) + L"\\";
}

extern "C" __declspec(dllexport)
bool __stdcall MapDriver(const wchar_t* driver_path)
{
    std::wstring exe = get_dir() + L"kdmapper.exe";

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

    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return code == 0;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
