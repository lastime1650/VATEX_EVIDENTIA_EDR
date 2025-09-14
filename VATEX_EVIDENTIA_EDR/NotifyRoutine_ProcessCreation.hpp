#ifndef NOTIFYROUTINE_PROCESS_H
#define NOTIFYROUTINE_PROCESS_H

#include "util.hpp"
#include "LogSender.hpp"

namespace EDR
{
	namespace NotifyRoutines
	{
		namespace Handler
		{
			extern "C" VOID ProcessCreateRoutineEx_HANDLER(
				_Inout_ PEPROCESS Process,
				_In_ HANDLE ProcessId,
				_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
			);
		}

		namespace ProcessCreation
		{
			

			namespace Load
			{
				NTSTATUS Load_NotifyRoutine_ProcessCreate();
			}
			namespace UnLoad
			{
				NTSTATUS UnLoad_NotifyRoutine_ProcessCreate();
			}
			
			


		}
	}
}

#endif