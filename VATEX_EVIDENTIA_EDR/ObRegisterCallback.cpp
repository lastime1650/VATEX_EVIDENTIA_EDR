#include "ObRegisterCallback.hpp"
#include "API.hpp"
#include "IOCTL.hpp"
#include "LogSender.hpp"

namespace EDR
{
	namespace ObRegisterCallback
	{

		OB_CALLBACK_REGISTRATION g_CallbackRegistration;
		PVOID g_CallbackHandle = NULL;

		namespace Handler
		{
			extern "C" OB_PREOP_CALLBACK_STATUS PreOperationCallback(
				_In_ PVOID RegistrationContext,
				_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
			) {
				// >= APC_LEVEL

				// Ŀ���ڵ��̸� Ŀ�ο��� ��û�� ���̹Ƿ� �����Ѵ�.
				/*
					Ŀ�ο��� PID -> HANDLE���� ��, "�������"�� �߻��� �� ����
				*/
				if(OperationInformation->KernelHandle)
					return OB_PREOP_SUCCESS;

				UNREFERENCED_PARAMETER(RegistrationContext);
				

				ULONG64 Nano_Timestamp = EDR::Util::Timestamp::Get_LocalTimestamp_Nano();

				HANDLE Self_ProcessId = PsGetCurrentProcessId();
				HANDLE Target_ProcessId = NULL;
				ULONG32 DesiredAccess = 0;
				BOOLEAN is_CreateHandleInformation = FALSE;

				if (PsIsSystemProcess(PsGetCurrentProcess()))
					return OB_PREOP_SUCCESS;

				// if AGENT User, skip !@
				if (Self_ProcessId == EDR::IOCTL::IOCTL_PROCESSING::resource::User_AGENT_ProcessId)
					return OB_PREOP_SUCCESS;

				// Process Event
				if (OperationInformation->ObjectType == *PsProcessType) {
					/*

						���μ��� �۾��� ���

					*/
					PEPROCESS Process = (PEPROCESS)OperationInformation->Object; // �� �̰ɷ� PID ������ 
					Target_ProcessId = PsGetProcessId(Process); // Self -> Target 

					if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
					{
						is_CreateHandleInformation = TRUE;
						DesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess; // ���ٱ���Ȯ��
					}
					else
					{
						is_CreateHandleInformation = FALSE;
						DesiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess; // ���ٱ���Ȯ��
					}



					// ����.. AGENT User ���μ����� �����Ϸ��� ������?? ������, ��ȣ 
					if (Target_ProcessId == EDR::IOCTL::IOCTL_PROCESSING::resource::User_AGENT_ProcessId)
					{

						if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
						{
							OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE; // ���� ������ ��������.(�ܺηκ��� �������Ẹȣ) (* �� Ŀ�ο��� ���ſ�û�ϸ� ������. �̶��� "�����۹�����"���� �䱸)
						}
						else
						{
							OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
						}
					}

					EDR::LogSender::function::ObRegisterCallbackLog(
						Self_ProcessId,
						Nano_Timestamp,

						is_CreateHandleInformation,
						DesiredAccess,
						Target_ProcessId
					);

				}

				return OB_PREOP_SUCCESS;
			}
		}
		


		NTSTATUS Load_ObRegisterCallbacks()
		{
			// ������
			UNICODE_STRING altitude;
			RtlInitUnicodeString(&altitude, ObRegisterCallbacks_Altitude); // ������ altitude ���ڿ� ���

			OB_OPERATION_REGISTRATION operations[] = {
				{ PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE , Handler::PreOperationCallback, NULL } // ���μ��� ����͸�
			};

			g_CallbackRegistration;
			g_CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
			g_CallbackRegistration.OperationRegistrationCount = ARRAYSIZE(operations);
			g_CallbackRegistration.Altitude = altitude;
			g_CallbackRegistration.RegistrationContext = NULL;
			g_CallbackRegistration.OperationRegistration = operations;

			return ObRegisterCallbacks(&g_CallbackRegistration, &g_CallbackHandle);
		}

		VOID CleanUp_ObRegisterCallbacks()
		{
			if (g_CallbackHandle)
				ObUnRegisterCallbacks(g_CallbackHandle);
		}
	}
}
