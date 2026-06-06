#include <ntifs.h>
#include <wdm.h>
#include "ioctl.h"

PDEVICE_OBJECT g_device = NULL;
PEPROCESS      g_target = NULL;

extern NTSTATUS DispatchControl(PIRP Irp, PIO_STACK_LOCATION Stack);

NTKERNELAPI extern LIST_ENTRY PsLoadedModuleList;

typedef struct _MY_LDR_ENTRY
{
    LIST_ENTRY  InLoadOrderLinks;
    PVOID       ExceptionTable;
    ULONG       ExceptionTableSize;
    ULONG       Padding;
    PVOID       GpValue;
    PVOID       NonPagedDebugInfo;
    PVOID       DllBase;
} MY_LDR_ENTRY;

#pragma pack(push, 1)
typedef struct { USHORT e_magic; UCHAR pad[58]; LONG e_lfanew; } MY_DOS_HDR;
typedef struct { ULONG Sig; UCHAR pad[20]; USHORT Magic; UCHAR pad2[110];
                 ULONG DataDir[32]; } MY_NT_HDR;
typedef struct { ULONG Chars; ULONG TimeDateStamp; ULONG MajorMinor; ULONG Name;
                 ULONG Base; ULONG NumFuncs; ULONG NumNames; ULONG AddrFuncs;
                 ULONG AddrNames; ULONG AddrOrdinals; } MY_EXPORT_DIR;
#pragma pack(pop)

static PVOID FindExport(PVOID base, const char* name)
{
    MY_DOS_HDR*    dos  = (MY_DOS_HDR*)base;
    MY_NT_HDR*     nt   = (MY_NT_HDR*)((ULONG_PTR)base + dos->e_lfanew);
    ULONG          rva  = nt->DataDir[0];
    if (!rva) return NULL;
    MY_EXPORT_DIR* exp  = (MY_EXPORT_DIR*)((ULONG_PTR)base + rva);
    ULONG*  funcs  = (ULONG* )((ULONG_PTR)base + exp->AddrFuncs);
    ULONG*  names  = (ULONG* )((ULONG_PTR)base + exp->AddrNames);
    USHORT* ords   = (USHORT*)((ULONG_PTR)base + exp->AddrOrdinals);
    for (ULONG i = 0; i < exp->NumNames; i++)
    {
        const char* en = (const char*)((ULONG_PTR)base + names[i]);
        const char* a = name; const char* b = en;
        while (*a && *a == *b) { a++; b++; }
        if (*a == *b) return (PVOID)((ULONG_PTR)base + funcs[ords[i]]);
    }
    return NULL;
}

typedef NTSTATUS(*tIoCreateDriver)(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE Init);

static tIoCreateDriver GetIoCreateDriver(void)
{
    MY_LDR_ENTRY* entry = CONTAINING_RECORD(
        PsLoadedModuleList.Flink, MY_LDR_ENTRY, InLoadOrderLinks);
    PVOID base = entry->DllBase;
    DbgPrint("[cr] ntoskrnl base: %p\n", base);
    if (!base) return NULL;
    tIoCreateDriver fn = (tIoCreateDriver)FindExport(base, "IoCreateDriver");
    DbgPrint("[cr] IoCreateDriver: %p\n", fn);
    return fn;
}

static NTSTATUS DeviceOffline(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_DEVICE_NOT_CONNECTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_DEVICE_NOT_CONNECTED;
}

VOID DriverSelfUnload(VOID)
{
    UNICODE_STRING lnk;
    RtlInitUnicodeString(&lnk, CR_DEVICE_LINK);
    IoDeleteSymbolicLink(&lnk);

    if (g_target) { ObDereferenceObject(g_target); g_target = NULL; }

    if (g_device && g_device->DriverObject)
    {
        for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
            g_device->DriverObject->MajorFunction[i] = DeviceOffline;
    }
    DbgPrint("[cr] driver unloaded (symlink removed, device offline)\n");
}

static VOID Cleanup(VOID)
{
    UNICODE_STRING lnk;
    RtlInitUnicodeString(&lnk, CR_DEVICE_LINK);
    IoDeleteSymbolicLink(&lnk);
    if (g_target) { ObDereferenceObject(g_target); g_target = NULL; }
    if (g_device) { IoDeleteDevice(g_device);       g_device = NULL; }
}

DRIVER_UNLOAD DriverUnload;
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    Cleanup();
}

DRIVER_DISPATCH DefaultDispatch;
NTSTATUS DefaultDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

DRIVER_DISPATCH DeviceControl;
NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return DispatchControl(Irp, IoGetCurrentIrpStackLocation(Irp));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    if (DriverObject == NULL)
    {
        tIoCreateDriver pIoCreateDriver = GetIoCreateDriver();
        if (!pIoCreateDriver) return STATUS_NOT_FOUND;

        DbgPrint("[cr] calling IoCreateDriver @ %p\n", pIoCreateDriver);
        NTSTATUS st = pIoCreateDriver(NULL, DriverEntry);
        DbgPrint("[cr] IoCreateDriver returned: 0x%X\n", st);
        return st;
    }

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DefaultDispatch;

    DriverObject->DriverUnload                          = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DefaultDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DefaultDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = DefaultDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

    UNICODE_STRING device_link;
    RtlInitUnicodeString(&device_link, CR_DEVICE_LINK);

    IoDeleteSymbolicLink(&device_link);
    UNICODE_STRING old_link;
    RtlInitUnicodeString(&old_link, L"\\DosDevices\\RvKit");
    IoDeleteSymbolicLink(&old_link);

    static const WCHAR* const k_dev_names[] = {
        L"\\Device\\RvKit",
        L"\\Device\\RvKit1",
        L"\\Device\\RvKit2",
        L"\\Device\\RvKit3",
        L"\\Device\\RvKit4",
    };
    static const int k_dev_count = sizeof(k_dev_names) / sizeof(k_dev_names[0]);

    UNICODE_STRING  device_name;
    NTSTATUS        status = STATUS_OBJECT_NAME_COLLISION;

    for (int i = 0; i < k_dev_count && status == STATUS_OBJECT_NAME_COLLISION; i++)
    {
        RtlInitUnicodeString(&device_name, k_dev_names[i]);

        PFILE_OBJECT   fo  = NULL;
        PDEVICE_OBJECT dev = NULL;
        if (NT_SUCCESS(IoGetDeviceObjectPointer(&device_name,
                FILE_READ_ATTRIBUTES, &fo, &dev)))
        {
            ObDereferenceObject(fo);
            IoDeleteDevice(dev);
        }

        status = IoCreateDevice(DriverObject, 0, &device_name,
                    FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
                    FALSE, &g_device);
        DbgPrint("[cr] IoCreateDevice(%wZ) = 0x%X\n", &device_name, status);
    }

    if (!NT_SUCCESS(status)) return status;

    g_device->Flags |= DO_BUFFERED_IO;
    g_device->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateSymbolicLink(&device_link, &device_name);
    DbgPrint("[cr] IoCreateSymbolicLink(%wZ -> %wZ) = 0x%X\n",
             &device_link, &device_name, status);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(g_device);
        g_device = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}
