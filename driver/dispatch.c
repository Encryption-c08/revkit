#include <ntifs.h>
#include <wdm.h>
#include "ioctl.h"

extern PEPROCESS      g_target;
extern PDEVICE_OBJECT g_device;

extern VOID DriverSelfUnload(VOID);

extern NTSTATUS OpAttach(ULONG Pid);
extern NTSTATUS OpDetach(void);
extern NTSTATUS OpRead(ULONG64 Address, ULONG64 Size, PVOID OutBuf, PULONG64 BytesRead);
extern NTSTATUS OpWrite(ULONG64 Address, ULONG64 Size, PVOID Data, PULONG64 BytesWritten);
extern NTSTATUS OpQuery(ULONG64 Address, CR_QUERY_OUT* Out);
extern NTSTATUS OpWritePhysical(ULONG64 VirtAddr, ULONG64 Size, PVOID Data);

NTSTATUS DispatchControl(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    PVOID  buf     = Irp->AssociatedIrp.SystemBuffer;
    ULONG  in_len  = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG  out_len = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG  code    = Stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG_PTR info = 0;
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    switch (code)
    {

    case CR_IOCTL_ATTACH:
        if (in_len < sizeof(CR_ATTACH_IN)) break;
        {
            CR_ATTACH_IN* req = (CR_ATTACH_IN*)buf;
            status = OpAttach(req->pid);
        }
        break;

    case CR_IOCTL_DETACH:
        status = OpDetach();
        break;

    case CR_IOCTL_READ:
        if (in_len < sizeof(CR_READ_IN)) break;
        {
            CR_READ_IN* req = (CR_READ_IN*)buf;
            if (out_len < req->size) { status = STATUS_BUFFER_TOO_SMALL; break; }
            ULONG64 bytes_read = 0;
            status = OpRead(req->address, req->size, buf, &bytes_read);
            info = (ULONG_PTR)bytes_read;
        }
        break;

    case CR_IOCTL_WRITE:
        if (in_len < sizeof(CR_WRITE_IN)) break;
        {
            CR_WRITE_IN* hdr = (CR_WRITE_IN*)buf;
            if (in_len < sizeof(CR_WRITE_IN) + hdr->size) break;
            PVOID data = (PUCHAR)buf + sizeof(CR_WRITE_IN);
            ULONG64 bytes_written = 0;
            status = OpWrite(hdr->address, hdr->size, data, &bytes_written);
            info = (ULONG_PTR)bytes_written;
        }
        break;

    case CR_IOCTL_QUERY:
        if (in_len < sizeof(CR_QUERY_IN) || out_len < sizeof(CR_QUERY_OUT)) break;
        {
            CR_QUERY_IN* req = (CR_QUERY_IN*)buf;
            status = OpQuery(req->address, (CR_QUERY_OUT*)buf);
            if (NT_SUCCESS(status)) info = sizeof(CR_QUERY_OUT);
        }
        break;

    case CR_IOCTL_WRITE_PHYSICAL:
        if (in_len < sizeof(CR_WRITE_PHYS_IN)) break;
        {
            CR_WRITE_PHYS_IN* hdr = (CR_WRITE_PHYS_IN*)buf;
            if (in_len < sizeof(CR_WRITE_PHYS_IN) + hdr->size) break;
            PVOID data = (PUCHAR)buf + sizeof(CR_WRITE_PHYS_IN);
            status = OpWritePhysical(hdr->address, hdr->size, data);
        }
        break;

    case CR_IOCTL_UNLOAD:
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        DriverSelfUnload();
        return STATUS_SUCCESS;

    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
