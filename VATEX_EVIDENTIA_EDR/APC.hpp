#ifndef APC_H
#define APC_H

#include <ntifs.h>
#include "API.hpp"

#define APC_ALLOC_TAG 'APCu'

namespace EDR
{
	namespace APC
	{
		namespace resource
		{
			extern PETHREAD USER_Thread;
			extern PKNORMAL_ROUTINE USER_APC_HANDLER; // IOCTL 유저의 가상주소인 APC 함수주소

			extern BOOLEAN is_working_apc;

			extern PFAST_MUTEX mutex;
		}
		

		BOOLEAN INITIALIZE_APC(HANDLE USER_ThreadID, PVOID USER_APC_Handler); // APC 전역정보 초기화
		BOOLEAN ApcToUser(ULONG64 cmd, PVOID UserAllocatedData);// APC 큐기반 유저모드에게 비동기적 데이터 전송
		VOID CleanUp_APC();

		
	}
}

extern "C" VOID NTAPI KernelApcCleanup(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);

#endif