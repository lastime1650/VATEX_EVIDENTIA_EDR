#ifndef IOCTL_INIT_H
#define IOCTL_INIT_H

#include "util.hpp"
#include "ioctl_codes.hpp"

#define IOCTL_DeviceName L"\\Device\\VATEX_EVIDENTIA_EDR_AGENT"
#define IOCTL_Device_SymbolicName L"\\??\\VATEX_EVIDENTIA_EDR_AGENT"

// IOCTL_PROCESSING
#include "APC.hpp"

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
			namespace resource
			{
				
				extern HANDLE User_AGENT_ProcessId;
				extern HANDLE User_AGENT_Process_Handle;

				namespace function
				{
					VOID Set_User_AGENT_INFO(HANDLE AGENT_pid, HANDLE AGENT_handle);
					VOID Get_User_AGENT_INFO(HANDLE* User_AGENT_ProcessId, HANDLE* User_AGENT_Process_Handle);
				}
			}

			// IOCTL_INIT
			NTSTATUS INITIALIZE(struct IOCTL_INIT_s* parameter1);


			VOID CleanUp_IOCTL_PROCESSING();
		}

	}
}

extern "C" NTSTATUS RequiredRoutine(PDEVICE_OBJECT pDeviceObject, PIRP Irp);

#endif