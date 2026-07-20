#pragma once
#include <windows.h>
#include <winioctl.h>
#include <cstdint>
#include <string>
#include "../util/xorstr.hpp"

#define CR_DEVICE_TYPE   FILE_DEVICE_UNKNOWN

#define CR_IOCTL_ATTACH         CTL_CODE(CR_DEVICE_TYPE, 0xA11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_DETACH         CTL_CODE(CR_DEVICE_TYPE, 0xA12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_READ           CTL_CODE(CR_DEVICE_TYPE, 0xA13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_WRITE          CTL_CODE(CR_DEVICE_TYPE, 0xA14, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_QUERY          CTL_CODE(CR_DEVICE_TYPE, 0xA15, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_UNLOAD         CTL_CODE(CR_DEVICE_TYPE, 0xA16, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_WRITE_PHYSICAL CTL_CODE(CR_DEVICE_TYPE, 0xA1D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_KERNEL_READ    CTL_CODE(CR_DEVICE_TYPE, 0xA1E, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
struct CrAttachIn     { uint32_t pid;                                                           };
struct CrReadIn       { uint64_t address; uint64_t size;                                        };
struct CrWriteIn      { uint64_t address; uint64_t size;                                        };
struct CrQueryIn      { uint64_t address;                                                       };
struct CrWritePhysIn  { uint64_t address; uint64_t size;                                        };
struct CrQueryOut     { uint64_t base; uint64_t size; uint32_t protect; uint32_t type; uint32_t state; };
#pragma pack(pop)

inline uint32_t cr_get_seed()
{
    // must match DRV_SEED in driver/driver.c exactly
    return 0x7E4A9C3Fu;
}

inline std::string cr_device_path()
{
    char buf[40];
    sprintf_s(buf, "\\\\.\\Global\\%08X", cr_get_seed());
    return buf;
}
