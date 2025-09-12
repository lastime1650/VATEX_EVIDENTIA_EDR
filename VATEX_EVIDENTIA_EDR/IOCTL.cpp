#include "IOCTL.hpp"



namespace EDR
{
	namespace IOCTL
	{
		namespace resource
		{
			PDEVICE_OBJECT ioctl_device;
		}

		NTSTATUS INITIALIZE(PDRIVER_OBJECT DriverObject)
		{
			if (!DriverObject)
				return NULL;

			resource::ioctl_device = NULL;
			UNICODE_STRING DeviceName;
			UNICODE_STRING SymbolicLinkName;
			NTSTATUS status;

			RtlInitUnicodeString(&DeviceName, IOCTL_DeviceName);
			RtlInitUnicodeString(&SymbolicLinkName, IOCTL_Device_SymbolicName);

			status = IoCreateDevice(
				DriverObject,
				0,
				&DeviceName,
				FILE_DEVICE_UNKNOWN,
				FILE_DEVICE_SECURE_OPEN,
				FALSE,
				&resource::ioctl_device
			);
			if (!NT_SUCCESS(status)) {
				return status;
			}

			status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
			if (!NT_SUCCESS(status)) {
				IoDeleteDevice(resource::ioctl_device);
				return status;
			}


			// 디스패치 등록
			DriverObject->MajorFunction[IRP_MJ_CREATE] = RequiredRoutine; // 필수 요건
			DriverObject->MajorFunction[IRP_MJ_CLOSE] = RequiredRoutine; // 필수 요건

			DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Dispatch::IOCTL_Dispatch; // IOCTL ! 

			// Final STEP) 디바이스 활성화
			resource::ioctl_device->Flags &= ~DO_DEVICE_INITIALIZING;


			return status; 
		}
		VOID CleanUp_IOCTL()
		{
			if (resource::ioctl_device)
			{
				UNICODE_STRING symbolic;
				RtlInitUnicodeString(&symbolic, IOCTL_Device_SymbolicName);

				IoDeleteSymbolicLink(&symbolic);
				IoDeleteDevice(resource::ioctl_device);
			}
			
			IOCTL_PROCESSING::CleanUp_IOCTL_PROCESSING();
		}

		/*
			유저모드간 통신 처리 
		*/
		namespace Dispatch
		{
			extern "C" NTSTATUS IOCTL_Dispatch(PDEVICE_OBJECT pDeviceObject, PIRP Irp) // called by User
			{
				if (!Irp || !pDeviceObject) return STATUS_UNSUCCESSFUL;

				NTSTATUS status = STATUS_SUCCESS;
				PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp); // Request Information

				ULONG_PTR IoStatusInformation = 0;

				switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
				{
					case IOCTL_INIT:
					{
						struct IOCTL_INIT_s* parameter = (struct IOCTL_INIT_s*)Irp->AssociatedIrp.SystemBuffer;
						if (!parameter) break;

						parameter->output.is_success = IOCTL_PROCESSING::INITIALIZE(parameter);

						IoStatusInformation = sizeof(struct IOCTL_INIT_s);
						break;
					}
					default:
					{
						status = STATUS_UNSUCCESSFUL;
					}
						
				}

				Irp->IoStatus.Status = status;
				Irp->IoStatus.Information = IoStatusInformation;

				return status;
			}
		}

		/*
			USER -> KERNEL( IOCTL_PROCESSING ) -> USER
		*/
		namespace IOCTL_PROCESSING
		{
			BOOLEAN is_complete_init = FALSE;
			namespace resource
			{
				HANDLE User_AGENT_ProcessId = 0;
				HANDLE User_AGENT_Process_Handle = NULL;
			}
			VOID CleanUp_IOCTL_PROCESSING()
			{
				if (!resource::User_AGENT_Process_Handle)
					EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(resource::User_AGENT_Process_Handle);
			}

			NTSTATUS INITIALIZE(struct IOCTL_INIT_s* parameter1)
			{
				NTSTATUS status;
				HANDLE User_ProcessId = parameter1->input.User_AGENT_ProcessId;

				
				HANDLE User_ThreadId = parameter1->input.User_APC_ThreadId;
				PVOID User_APC_Routine = parameter1->input.User_APC_Handler_UserAddress;

				// USER PID
				resource::User_AGENT_ProcessId = User_ProcessId;

				// USER PID -> HANDLE( 없는 경우 최초 1회진행 ) 
				if (!resource::User_AGENT_Process_Handle)
				{
					status = EDR::Util::Process::Handle::LookupProcessHandlebyProcessId(User_ProcessId, &resource::User_AGENT_Process_Handle);
					if (!NT_SUCCESS(status))
					{
						is_complete_init = FALSE;
						return status;
					}
						
				}
				
				// APC
				status = EDR::APC::INITIALIZE_APC(User_ThreadId, User_APC_Routine);
				if (!NT_SUCCESS(status))
				{
					is_complete_init = FALSE;
					return status;
				}


				is_complete_init = TRUE;
				return status;
			}
		}
	}
}


extern "C" NTSTATUS RequiredRoutine(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	// NOTHING TO DO !!!!

	return STATUS_SUCCESS;
}