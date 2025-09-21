#ifndef IOCTL_INIT_H
#define IOCTL_INIT_H

#include "util.hpp"
#include "ioctl_codes.hpp"

#define IOCTL_DeviceName L"\\Device\\VATEX_EVIDENTIA_EDR_AGENT"
#define IOCTL_Device_SymbolicName L"\\??\\VATEX_EVIDENTIA_EDR_AGENT"

// IOCTL_PROCESSING
#include "APC.hpp"
#include "LogSender.hpp"

namespace EDR
{
	namespace IOCTL
	{
		namespace resource
		{
			extern PDEVICE_OBJECT ioctl_device;
		}

		NTSTATUS INITIALIZE(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT* out);
		VOID CleanUp_IOCTL();

		namespace Dispatch
		{
			extern "C" NTSTATUS IOCTL_Dispatch(PDEVICE_OBJECT pDeviceObject, PIRP Irp); // called by User
		}


		namespace IOCTL_PROCESSING
		{
			extern BOOLEAN is_complete_init;

			// IOCTL_INIT
			BOOLEAN INITIALIZE(
				struct IOCTL_INIT_s* parameter1
			);

			// IOCTL_LOG ��û
			BOOLEAN REQUEST_LOG( _Out_ PUCHAR* StartBUff, _Out_ ULONG64* SIze);

			// ���� ��û
			// ���� �� Ŭ �� �ֱ� ������, ���Ḯ��Ʈ�� ������忡 ����. 
			PVOID REQUEST_FILE(const PCHAR FilePath, SIZE_T FIlePathBuffer);

		}

	}
}

extern "C" NTSTATUS RequiredRoutine(PDEVICE_OBJECT pDeviceObject, PIRP Irp);

#endif