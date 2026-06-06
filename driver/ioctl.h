#pragma once
#include <ntdef.h>

#define CR_DEVICE_NAME   L"\\Device\\RvKit"
#define CR_DEVICE_LINK   L"\\DosDevices\\Global\\RvKit"
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

typedef struct _CR_ATTACH_IN
{
    ULONG pid;
} CR_ATTACH_IN;

typedef struct _CR_READ_IN
{
    ULONG64 address;
    ULONG64 size;
} CR_READ_IN;

typedef struct _CR_WRITE_IN
{
    ULONG64 address;
    ULONG64 size;
} CR_WRITE_IN;

typedef struct _CR_QUERY_IN
{
    ULONG64 address;
} CR_QUERY_IN;

typedef struct _CR_QUERY_OUT
{
    ULONG64 base;
    ULONG64 size;
    ULONG   protect;
    ULONG   type;
    ULONG   state;
} CR_QUERY_OUT;

typedef struct _CR_WRITE_PHYS_IN
{
    ULONG64 address;
    ULONG64 size;
} CR_WRITE_PHYS_IN;

#pragma pack(pop)
