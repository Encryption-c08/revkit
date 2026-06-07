#pragma once
#include <Windows.h>
#include <string>
#include <filesystem>

namespace revkit::driver
{

static constexpr const char* k_service_name = "RvKit";
static constexpr const char* k_device_path  = "\\\\.\\RvKit";

inline bool install_and_start(const std::string& sys_path)
{
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;

    SC_HANDLE svc = CreateServiceA(
        scm, k_service_name, k_service_name,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        sys_path.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!svc)
    {
        svc = OpenServiceA(scm, k_service_name, SERVICE_ALL_ACCESS);
    }

    bool ok = false;
    if (svc)
    {
        SERVICE_STATUS ss{};
        QueryServiceStatus(svc, &ss);
        if (ss.dwCurrentState != SERVICE_RUNNING)
        {
            ok = StartServiceA(svc, 0, nullptr) != FALSE;
        }
        else
        {
            ok = true;
        }
        CloseServiceHandle(svc);
    }

    CloseServiceHandle(scm);
    return ok;
}

inline bool stop_and_remove()
{
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, k_service_name, SERVICE_ALL_ACCESS);
    bool ok = false;
    if (svc)
    {
        SERVICE_STATUS ss{};
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        ok = DeleteService(svc) != FALSE;
        CloseServiceHandle(svc);
    }

    CloseServiceHandle(scm);
    return ok;
}

inline bool is_device_present()
{
    HANDLE h = CreateFileA(k_device_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

inline std::string default_sys_path()
{
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::filesystem::path p(buf);
    return (p.parent_path() / "cr-driver.sys").string();
}

}
