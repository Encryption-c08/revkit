#pragma once
#include <Windows.h>
#include <string>

namespace revkit::util
{

inline bool hvci_is_enabled()
{
    DWORD val = 0, sz = sizeof(val);
    if (RegGetValueA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
            "Enabled", RRF_RT_DWORD, nullptr, &val, &sz) == ERROR_SUCCESS)
        return val != 0;
    sz = sizeof(val);
    if (RegGetValueA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            "EnableVirtualizationBasedSecurity", RRF_RT_DWORD, nullptr, &val, &sz) == ERROR_SUCCESS)
        return val != 0;
    return false;
}

inline bool blocklist_is_enabled()
{
    DWORD val = 1, sz = sizeof(val);
    RegGetValueA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
        "VulnerableDriverBlocklistEnable", RRF_RT_DWORD, nullptr, &val, &sz);
    return val != 0;
}

static bool reg_set_dword(HKEY root, const char* path, const char* name, DWORD value)
{
    HKEY key = nullptr;
    if (RegCreateKeyExA(root, path, 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return false;
    bool ok = RegSetValueExA(key, name, 0, REG_DWORD,
                             (const BYTE*)&value, sizeof(value)) == ERROR_SUCCESS;
    RegCloseKey(key);
    return ok;
}

inline bool disable_hvci_and_blocklist()
{
    bool changed = false;

    if (hvci_is_enabled())
    {
        reg_set_dword(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
            "Enabled", 0);
        reg_set_dword(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            "EnableVirtualizationBasedSecurity", 0);
        changed = true;
    }

    if (blocklist_is_enabled())
    {
        reg_set_dword(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
            "VulnerableDriverBlocklistEnable", 0);
        changed = true;
    }

    return changed;
}

inline bool reboot_now()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    LUID luid{};
    LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &luid);
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);

    return ExitWindowsEx(EWX_REBOOT | EWX_FORCE,
                         SHTDN_REASON_MAJOR_APPLICATION |
                         SHTDN_REASON_FLAG_PLANNED) != FALSE;
}

}
