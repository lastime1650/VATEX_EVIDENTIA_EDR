#pragma warning(disable:4312)
#ifndef APC_H
#define APC_H

#include "APC.hpp"
#include "Util.hpp"
#include "EventLog.hpp"

namespace EDR
{
	namespace APC
	{
		

		extern HANDLE ThreadHandle;

		extern "C" VOID NTAPI ApcHandler(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);

		HANDLE Init_APC(HANDLE* ThreadID, PVOID* User_APCHandler, EDR::Util::Queue::IQueue* logQueue);
		extern "C" DWORD APC_LOOP(PVOID context);
	}
}

#endif