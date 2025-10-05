#include "NotifyRoutine_ProcessCreation.hpp"

#include "API_Hook.hpp"
#include "API.hpp"

namespace EDR
{
	namespace NotifyRoutines
	{
		

		namespace ProcessCreation
		{

			namespace Handler
			{
				extern "C" VOID ProcessCreateRoutineEx_HANDLER(
					_Inout_ PEPROCESS Process,
					_In_ HANDLE ProcessId,
					_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
				)
				{
					if (!EDR::Util::Shared::USER_AGENT::ProcessId)
						return;

					PAGED_CODE();

					ULONG64 NanoTimestamp = EDR::Util::Timestamp::Get_LocalTimestamp_Nano();

					if (PsIsSystemProcess(Process))
						return;

					if (CreateInfo)
					{
						// 프로세스 생성

						// 시스템 프로세스의 경우 SKIP
						if (CreateInfo->IsSubsystemProcess)
							return;
						
						EDR::LogSender::function::ProcessCreateLog(
							ProcessId,
							NanoTimestamp,
							CreateInfo->ParentProcessId,
							CreateInfo->CommandLine
						);

						/*
						// API Hook
						HANDLE Thread = NULL;
						PsCreateSystemThread(
							&Thread,
							THREAD_ALL_ACCESS,
							NULL,
							NULL,
							NULL,
							EDR::APIHooking::Handler::API_Hooking_HANDLER,
							ProcessId
						);
						if (Thread)
							ZwClose(Thread); // 성공 시, Detach */
					}
					else
					{
						// 프로세스 종료
						EDR::LogSender::function::ProcessTerminateLog(
							ProcessId,
							NanoTimestamp
						);
					}
				}
			}


			BOOLEAN is_working = FALSE;
			namespace Load
			{
				NTSTATUS Load_NotifyRoutine_ProcessCreate()
				{
					NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(Handler::ProcessCreateRoutineEx_HANDLER, FALSE);
					if (!NT_SUCCESS(status))
						is_working = FALSE;
					else
						is_working = TRUE;

					return status;
				}
			}
			namespace UnLoad
			{
				NTSTATUS UnLoad_NotifyRoutine_ProcessCreate()
				{
					if (is_working)
						return PsSetCreateProcessNotifyRoutineEx(Handler::ProcessCreateRoutineEx_HANDLER, TRUE);

					return STATUS_UNSUCCESSFUL;
				}
			}
		}
	}
}