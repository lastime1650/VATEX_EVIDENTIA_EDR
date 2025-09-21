#include "IOCTL.hpp"



namespace EDR
{
	namespace IOCTL
	{
		namespace resource
		{
			PDEVICE_OBJECT ioctl_device;
		}

		NTSTATUS INITIALIZE(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT* out)
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

			if (out)
				*out = resource::ioctl_device;

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
				//debug_break();
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
					case IOCTL_REQ_LOG:
					{
						//debug_break();
						struct IOCTL_REQ_LOG_s* parameter = (struct IOCTL_REQ_LOG_s*)Irp->AssociatedIrp.SystemBuffer;
						if (!parameter) break;

						parameter->output.is_success = IOCTL_PROCESSING::REQUEST_LOG(&parameter->output.BufferAddress, &parameter->output.BUfferSize);

						//debug_log("LOG REQ : %p , %llu", parameter->output.BufferAddress, parameter->output.BUfferSize);

						IoStatusInformation = sizeof(struct IOCTL_REQ_LOG_s);
						break;
					}
					default:
					{
						status = STATUS_UNSUCCESSFUL;
					}
						
				}

				Irp->IoStatus.Status = status;
				Irp->IoStatus.Information = IoStatusInformation;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);

				return status;
			}
		}

		/*
			USER -> KERNEL( IOCTL_PROCESSING ) -> USER
		*/
		namespace IOCTL_PROCESSING
		{
			BOOLEAN is_complete_init = FALSE;
			
			// 1. 
			BOOLEAN INITIALIZE(struct IOCTL_INIT_s* parameter1)
			{
				NTSTATUS status;
				HANDLE User_ProcessId = parameter1->input.User_AGENT_ProcessId;

				
				HANDLE User_ThreadId = parameter1->input.User_APC_ThreadId;
				PVOID User_APC_Routine = parameter1->input.User_APC_Handler_UserAddress;

				// USER PID
				EDR::Util::Shared::USER_AGENT::ProcessId = User_ProcessId;

				// USER PID -> HANDLE( 이전에 있는 경우, 해제하고 갱신
				if (EDR::Util::Shared::USER_AGENT::ProcessHandle)
					EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(EDR::Util::Shared::USER_AGENT::ProcessHandle);

				status = EDR::Util::Process::Handle::LookupProcessHandlebyProcessId(User_ProcessId, &EDR::Util::Shared::USER_AGENT::ProcessHandle);
				if (!NT_SUCCESS(status))
				{
					is_complete_init = FALSE;
					return is_complete_init;
				}

				
				// APC
				status = EDR::APC::INITIALIZE_APC(User_ThreadId, User_APC_Routine);
				if (!NT_SUCCESS(status))
				{
					is_complete_init = FALSE;
					return is_complete_init;
				}


				is_complete_init = TRUE;
				return is_complete_init;
			}

			BOOLEAN REQUEST_LOG(_Out_ PUCHAR* StartBUff, _Out_ ULONG64* SIze)
			{
				return EDR::LogSender::resource::Consume::Consume(
					(PVOID*)StartBUff, 
					SIze
				);
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