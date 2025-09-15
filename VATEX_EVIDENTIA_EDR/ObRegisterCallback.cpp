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

				// 커널핸들이면 커널에서 요청한 것이므로 제외한다.
				/*
					커널에서 PID -> HANDLE얻을 때, "무한재귀"가 발생할 수 있음
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

						프로세스 작업인 경우

					*/
					PEPROCESS Process = (PEPROCESS)OperationInformation->Object; // 꼭 이걸로 PID 얻어야함 
					Target_ProcessId = PsGetProcessId(Process); // Self -> Target 

					if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
					{
						is_CreateHandleInformation = TRUE;
						DesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess; // 접근권한확인
					}
					else
					{
						is_CreateHandleInformation = FALSE;
						DesiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess; // 접근권한확인
					}



					// 설마.. AGENT User 프로세스를 종료하려는 것인지?? 검증후, 보호 
					if (Target_ProcessId == EDR::IOCTL::IOCTL_PROCESSING::resource::User_AGENT_ProcessId)
					{

						if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
						{
							OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE; // 종료 권한을 빼버리기.(외부로부터 강제종료보호) (* 단 커널에서 제거요청하면 못막음. 이때는 "하이퍼바이저"개발 요구)
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
			// 고도설정
			UNICODE_STRING altitude;
			RtlInitUnicodeString(&altitude, ObRegisterCallbacks_Altitude); // 고유한 altitude 문자열 사용

			OB_OPERATION_REGISTRATION operations[] = {
				{ PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE , Handler::PreOperationCallback, NULL } // 프로세스 모니터링
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
