#pragma warning (disable: 4028)

#include <ntifs.h>
#include <ntddk.h>

#define IOCTLTESTCODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x14563452, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

PDEVICE_OBJECT pDeviceObj;
UNICODE_STRING dev, dos;

ULONG procId, modAddress;

NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);


NTSTATUS Unload(PDRIVER_OBJECT pDriverObj)
{
	DbgPrint("Unload Routine Called\n");

	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObj->DeviceObject);
}

NTSTATUS Create(PDRIVER_OBJECT pDriverObj, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS Close(PDRIVER_OBJECT pDriverObj, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS IOCTL(PDEVICE_OBJECT pDeviceObj, PIRP Irp)
{
	NTSTATUS Status;
	ULONG BytesIO = 0;
	PIO_STACK_LOCATION IO;

	IO = IoGetCurrentIrpStackLocation(Irp);

	if (IO->Parameters.DeviceIoControl.IoControlCode = IOCTLTESTCODE) {
		DbgPrint("Test Coded Recieved");

		Status = STATUS_SUCCESS;
	} else {
		DbgPrint("Unknown Code");

		Status = STATUS_INVALID_PARAMETER;
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

// Working on
NTSTATUS KeReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(), TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

// Working on
NTSTATUS KeWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
		TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	DbgPrint("Driver Entry.");

	RtlInitUnicodeString(&dev, L"\\Device\\ioctl");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\ioctl");

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObj);
	IoCreateSymbolicLink(&dos, &dev);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTL;

	pDriverObject->DriverUnload = Unload;

	pDeviceObj->Flags |= DO_DIRECT_IO;
	pDeviceObj->Flags &= DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}