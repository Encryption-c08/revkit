#include <ntifs.h>
#include <wdm.h>
#include "ioctl.h"

extern PEPROCESS g_target;
extern ULONG      g_target_pid;

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    PEPROCESS        SourceProcess,
    PVOID            SourceAddress,
    PEPROCESS        TargetProcess,
    PVOID            TargetAddress,
    SIZE_T           BufferSize,
    KPROCESSOR_MODE  PreviousMode,
    PSIZE_T          NumberOfBytesTransferred
);


NTSTATUS OpAttach(ULONG Pid)
{
    if (g_target)
    {
        ObDereferenceObject(g_target);
        g_target = NULL;
    }
    g_target_pid = Pid;
    HANDLE hpid = ULongToHandle(Pid);
    NTSTATUS st = PsLookupProcessByProcessId(hpid, &g_target);
    if (!NT_SUCCESS(st))
        g_target_pid = 0;
    return st;
}

NTSTATUS OpDetach(void)
{
    if (g_target)
    {
        ObDereferenceObject(g_target);
        g_target = NULL;
    }
    g_target_pid = 0;
    return STATUS_SUCCESS;
}

NTSTATUS OpRead(ULONG64 Address, ULONG64 Size, PVOID OutBuf, PULONG64 BytesRead)
{
    if (!g_target) return STATUS_INVALID_HANDLE;
    SIZE_T transferred = 0;
    PEPROCESS current = PsGetCurrentProcess();
    NTSTATUS status = MmCopyVirtualMemory(
        g_target, (PVOID)(ULONG_PTR)Address,
        current,  OutBuf,
        (SIZE_T)Size, KernelMode, &transferred);
    *BytesRead = (ULONG64)transferred;
    return status;
}

NTSTATUS OpWrite(ULONG64 Address, ULONG64 Size, PVOID Data, PULONG64 BytesWritten)
{
    if (!g_target) return STATUS_INVALID_HANDLE;
    SIZE_T transferred = 0;
    PEPROCESS current = PsGetCurrentProcess();
    NTSTATUS status = MmCopyVirtualMemory(
        current, Data,
        g_target, (PVOID)(ULONG_PTR)Address,
        (SIZE_T)Size, KernelMode, &transferred);
    *BytesWritten = (ULONG64)transferred;
    return status;
}

NTSTATUS OpWritePhysical(ULONG64 VirtAddr, ULONG64 Size, PVOID Data)
{
    KAPC_STATE apc_state;
    PHYSICAL_ADDRESS phys;
    PVOID mapped;
    ULONG64 page_offset;
    ULONG64 map_size;
    NTSTATUS status = STATUS_SUCCESS;

    if (!g_target) return STATUS_INVALID_HANDLE;
    if (Size == 0 || Size > 4096) return STATUS_INVALID_PARAMETER;

    KeStackAttachProcess(g_target, &apc_state);
    phys = MmGetPhysicalAddress((PVOID)(ULONG_PTR)VirtAddr);
    KeUnstackDetachProcess(&apc_state);

    if (phys.QuadPart == 0) return STATUS_INVALID_ADDRESS;

    page_offset = VirtAddr & 0xFFF;
    map_size    = page_offset + Size;
    if (map_size > 0x2000) return STATUS_INVALID_PARAMETER;

    {
        PHYSICAL_ADDRESS page_base;
        page_base.QuadPart = phys.QuadPart & ~(LONGLONG)0xFFF;
        mapped = MmMapIoSpaceEx(page_base, (SIZE_T)map_size, PAGE_READWRITE);
        if (!mapped) return STATUS_INSUFFICIENT_RESOURCES;

        RtlCopyMemory((PUCHAR)mapped + page_offset, Data, (SIZE_T)Size);

        MmUnmapIoSpace(mapped, (SIZE_T)map_size);
    }

    return status;
}

NTSTATUS OpKernelRead(ULONG64 Address, ULONG64 Size, PVOID OutBuf, PULONG64 BytesRead)
{
    /* Max 4 MB per call — caller loops for larger ranges */
    if (Size == 0 || Size > 0x400000) return STATUS_INVALID_PARAMETER;

    *BytesRead = 0;

    /*
     * Read page-by-page.  MmIsAddressValid checks before every touch so we
     * never fault on a freed INIT section, paged-out region, or guard page.
     * RtlCopyMemory is kept inside __try as a second safety net but should
     * not be needed after the validity check.
     */
    ULONG64 done = 0;
    while (done < Size)
    {
        ULONG_PTR src = (ULONG_PTR)(Address + done);

        if (!MmIsAddressValid((PVOID)src))
            break;

        /* Never cross a page boundary in a single copy */
        ULONG64 page_off = src & 0xFFFULL;
        ULONG64 batch    = 0x1000ULL - page_off;
        if (done + batch > Size)
            batch = Size - done;

        __try
        {
            RtlCopyMemory((PUCHAR)OutBuf + done, (PVOID)src, (SIZE_T)batch);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            break;
        }

        done += batch;
    }

    *BytesRead = done;
    return (done > 0) ? STATUS_SUCCESS : STATUS_ACCESS_VIOLATION;
}

NTSTATUS OpQuery(ULONG64 Address, CR_QUERY_OUT* Out)
{
    if (!g_target) return STATUS_INVALID_HANDLE;

    HANDLE process_handle = NULL;
    NTSTATUS status = ObOpenObjectByPointer(
        g_target, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &process_handle);
    if (!NT_SUCCESS(status)) return status;

    MEMORY_BASIC_INFORMATION mbi;
    RtlZeroMemory(&mbi, sizeof(mbi));
    SIZE_T ret_len = 0;
    status = ZwQueryVirtualMemory(
        process_handle, (PVOID)(ULONG_PTR)Address,
        MemoryBasicInformation, &mbi, sizeof(mbi), &ret_len);

    ZwClose(process_handle);

    if (NT_SUCCESS(status))
    {
        Out->base    = (ULONG64)(ULONG_PTR)mbi.BaseAddress;
        Out->size    = (ULONG64)mbi.RegionSize;
        Out->protect = mbi.Protect;
        Out->type    = mbi.Type;
        Out->state   = mbi.State;
    }
    return status;
}
