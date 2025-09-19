#include "APC.hpp"
#include <iostream>

namespace EDR
{
	namespace q
	{
		EDR::Util::Queue::IQueue* logQueue = nullptr;
	}
	namespace APC
	{
		HANDLE ThreadHandle = 0;

		extern "C" VOID NTAPI ApcHandler(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
		{
			
			EventLog::Enum::EventLog_Enum type = (EventLog::Enum::EventLog_Enum)( (ULONG32)NormalContext);
			PVOID AllocatedLogData = SystemArgument1;
			ULONG64 AllocatedLogData_Size = (ULONG64)SystemArgument2;

			//std::cout << "NormalContext: " << type << " Arg1: " << AllocatedLogData << " Arg2: " << AllocatedLogData_Size << std::endl;

			EDR::EventLog::HandlerLog::HandlerLog_s log_s;

			log_s.type = type;

			log_s.logData = new unsigned char[AllocatedLogData_Size];
			memcpy(log_s.logData, AllocatedLogData, AllocatedLogData_Size);


			q::logQueue->putRaw(&log_s);

			VirtualFree(SystemArgument1, 0, MEM_RELEASE);
		}

		HANDLE Init_APC(HANDLE* ThreadID, PVOID* User_APCHandler, EDR::Util::Queue::IQueue* logQueue)
		{
			DWORD ThreadId = 0;
			ThreadHandle = CreateThread(
				NULL,
				0,
				APC_LOOP,
				NULL,
				0,
				&ThreadId
			);

			if (ThreadHandle == INVALID_HANDLE_VALUE)
			{
				return NULL;
			}

			*ThreadID = (HANDLE)ThreadId;
			*User_APCHandler = (PVOID)ApcHandler;

			q::logQueue = logQueue;

			std::cout << "ThreadID: " << ThreadId << std::endl;
			std::cout << "APCHandler:" << (PVOID)ApcHandler << std::endl;

			return ThreadHandle;

		}


		extern "C" DWORD APC_LOOP(PVOID context)
		{
			while (1)
			{
				WaitForSingleObjectEx(GetCurrentThread(), INFINITE, TRUE);
			}
		}
	}
}