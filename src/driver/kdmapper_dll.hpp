#pragma once
#include <windows.h>
#include <string>

namespace revkit::driver
{

class KdMapper
{
public:
    static bool map_driver(const std::wstring& driver_path);
    static bool is_available();

private:
    static HMODULE try_load_dll();
    static bool run_exe_fallback(const std::wstring& driver_path);
    static std::wstring get_exe_dir();
};

}
