#pragma once
#include <Windows.h>
#include <winioctl.h>
#include <cstdint>

#define CR_DEVICE_PATH   "\\\\.\\RvKit"
#define CR_DEVICE_TYPE   0x8000u

#define CR_IOCTL_ATTACH        CTL_CODE(CR_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_DETACH        CTL_CODE(CR_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_READ          CTL_CODE(CR_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_WRITE         CTL_CODE(CR_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_QUERY         CTL_CODE(CR_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_UNLOAD        CTL_CODE(CR_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CR_IOCTL_WRITE_PHYSICAL CTL_CODE(CR_DEVICE_TYPE, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)

struct CrAttachIn       { uint32_t pid; };
struct CrReadIn         { uint64_t address; uint64_t size; };
struct CrWriteIn        { uint64_t address; uint64_t size; };
struct CrQueryIn        { uint64_t address; };
struct CrQueryOut       { uint64_t base; uint64_t size; uint32_t protect; uint32_t type; uint32_t state; };
struct CrWritePhysIn    { uint64_t address; uint64_t size; };

#pragma pack(pop)
