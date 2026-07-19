#include <ntifs.h>
#include <wdm.h>
#include "ioctl.h"

PDEVICE_OBJECT g_device = NULL;
PEPROCESS      g_target = NULL;
ULONG          g_target_pid = 0;

static WCHAR g_dev_name[32] = {0};
static WCHAR g_dev_link[48] = {0};

extern NTSTATUS DispatchControl(PIRP Irp, PIO_STACK_LOCATION Stack);

NTKERNELAPI extern LIST_ENTRY PsLoadedModuleList;

typedef struct _MY_LDR_ENTRY
{
    LIST_ENTRY  InLoadOrderLinks;
    PVOID       InMemFlink;
    PVOID       InMemBlink;
    PVOID       InInitFlink;
    PVOID       InInitBlink;
    PVOID       DllBase;
} MY_LDR_ENTRY;

#pragma pack(push, 1)
typedef struct { USHORT e_magic; UCHAR pad[58]; LONG e_lfanew; } MY_DOS_HDR;
typedef struct { ULONG Sig; UCHAR pad[20]; USHORT Magic; UCHAR pad2[110]; ULONG DataDir[32]; } MY_NT_HDR;
typedef struct { ULONG Chars; ULONG TimeDateStamp; ULONG MajorMinor; ULONG Name;
                 ULONG Base; ULONG NumFuncs; ULONG NumNames; ULONG AddrFuncs;
                 ULONG AddrNames; ULONG AddrOrdinals; } MY_EXPORT_DIR;
#pragma pack(pop)

static UCHAR xk_b(int i)
{
    return (UCHAR)((0x4B ^ ((0x7F + i) & 0xFF) ^ ((0x21 * ((i | 1) & 0xFF)) & 0xFF)) & 0xFF);
}

static void xdec_b(char* out, const UCHAR* enc, int n)
{
    for (int i = 0; i < n; i++) out[i] = (char)(enc[i] ^ xk_b(i));
    out[n] = '\0';
}

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
    ULONG i;
    for (i = 0; i < exp->NumNames; i++)
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
    MY_LDR_ENTRY* entry = CONTAINING_RECORD(PsLoadedModuleList.Flink, MY_LDR_ENTRY, InLoadOrderLinks);
    PVOID base = entry->DllBase;
    if (!base) return NULL;

    static const UCHAR k_icd_enc[] = {
        0x5C, 0x85, 0xEA, 0xD8, 0x08, 0x0B, 0x5D, 0x4F,
        0xA1, 0x98, 0xC0, 0xDC, 0x08, 0x18, 0x29
    };
    char icd[16];
    xdec_b(icd, k_icd_enc, 14);
    return (tIoCreateDriver)FindExport(base, icd);
}

/*
 * Fixed seed used by both kernel and usermode to compute the device name.
 * Both sides call: sprintf("\\\\.\\%08X", DRV_SEED) -> \\.\7E4A9C3F
 * No plaintext device name string appears in either binary.
 */
#define DRV_SEED 0x7E4A9C3Fu

static const WCHAR g_hex[] = L"0123456789ABCDEF";

static void build_names(void)
{
    WCHAR suffix[9];
    ULONG s = DRV_SEED;
    int i, j;

    for (i = 7; i >= 0; i--) { suffix[i] = g_hex[s & 0xF]; s >>= 4; }
    suffix[8] = L'\0';

    i = 0;
    g_dev_name[i++] = L'\\'; g_dev_name[i++] = L'D'; g_dev_name[i++] = L'e';
    g_dev_name[i++] = L'v';  g_dev_name[i++] = L'i'; g_dev_name[i++] = L'c';
    g_dev_name[i++] = L'e';  g_dev_name[i++] = L'\\';
    for (j = 0; j < 8; j++) g_dev_name[i++] = suffix[j];
    g_dev_name[i] = L'\0';

    i = 0;
    g_dev_link[i++] = L'\\'; g_dev_link[i++] = L'D'; g_dev_link[i++] = L'o';
    g_dev_link[i++] = L's';  g_dev_link[i++] = L'D'; g_dev_link[i++] = L'e';
    g_dev_link[i++] = L'v';  g_dev_link[i++] = L'i'; g_dev_link[i++] = L'c';
    g_dev_link[i++] = L'e';  g_dev_link[i++] = L's'; g_dev_link[i++] = L'\\';
    g_dev_link[i++] = L'G';  g_dev_link[i++] = L'l'; g_dev_link[i++] = L'o';
    g_dev_link[i++] = L'b';  g_dev_link[i++] = L'a'; g_dev_link[i++] = L'l';
    g_dev_link[i++] = L'\\';
    for (j = 0; j < 8; j++) g_dev_link[i++] = suffix[j];
    g_dev_link[i] = L'\0';
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
    PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);
    RtlInitUnicodeString(&lnk, g_dev_link);
    IoDeleteSymbolicLink(&lnk);
    if (g_target) { ObDereferenceObject(g_target); g_target = NULL; }
    if (g_device && g_device->DriverObject)
    {
        ULONG i;
        for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
            g_device->DriverObject->MajorFunction[i] = DeviceOffline;
    }
}

static VOID ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);
    if (Create)
        return;
    if (ProcessId == (HANDLE)(ULONG_PTR)g_target_pid)
    {
        if (g_target) { ObDereferenceObject(g_target); g_target = NULL; }
        g_target_pid = 0;
    }
}

static VOID Cleanup(VOID)
{
    PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);
    UNICODE_STRING lnk;
    RtlInitUnicodeString(&lnk, g_dev_link);
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
        return pIoCreateDriver(NULL, DriverEntry);
    }

    build_names();

    {
        ULONG i;
        for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
            DriverObject->MajorFunction[i] = DefaultDispatch;
    }

    DriverObject->DriverUnload                          = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DefaultDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DefaultDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = DefaultDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

    UNICODE_STRING device_name;
    UNICODE_STRING device_link;
    RtlInitUnicodeString(&device_name, g_dev_name);
    RtlInitUnicodeString(&device_link, g_dev_link);

    IoDeleteSymbolicLink(&device_link);

    NTSTATUS status = IoCreateDevice(
        DriverObject, 0, &device_name,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_device);

    if (!NT_SUCCESS(status))
    {
        WCHAR alt_name[32];
        ULONG s2 = DRV_SEED + 1u;
        WCHAR suf2[9];
        int i, j;
        for (i = 7; i >= 0; i--) { suf2[i] = g_hex[s2 & 0xF]; s2 >>= 4; }
        suf2[8] = L'\0';
        i = 0;
        alt_name[i++] = L'\\'; alt_name[i++] = L'D'; alt_name[i++] = L'e';
        alt_name[i++] = L'v';  alt_name[i++] = L'i'; alt_name[i++] = L'c';
        alt_name[i++] = L'e';  alt_name[i++] = L'\\';
        for (j = 0; j < 8; j++) alt_name[i++] = suf2[j];
        alt_name[i] = L'\0';

        UNICODE_STRING alt_ustr;
        RtlInitUnicodeString(&alt_ustr, alt_name);
        status = IoCreateDevice(
            DriverObject, 0, &alt_ustr,
            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_device);

        if (!NT_SUCCESS(status)) return status;
        RtlCopyUnicodeString(&device_name, &alt_ustr);
    }

    g_device->Flags |= DO_BUFFERED_IO;
    g_device->Flags &= ~DO_DEVICE_INITIALIZING;

    PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, FALSE);

    status = IoCreateSymbolicLink(&device_link, &device_name);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(g_device);
        g_device = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}
