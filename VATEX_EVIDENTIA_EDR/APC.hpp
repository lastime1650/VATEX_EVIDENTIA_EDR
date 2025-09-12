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
			extern PKNORMAL_ROUTINE USER_APC_HANDLER; // IOCTL ������ �����ּ��� APC �Լ��ּ�

			extern BOOLEAN is_working_apc;

			extern PFAST_MUTEX mutex;
		}
		

		BOOLEAN INITIALIZE_APC(HANDLE USER_ThreadID, PVOID USER_APC_Handler); // APC �������� �ʱ�ȭ
		BOOLEAN ApcToUser(ULONG64 cmd, PVOID UserAllocatedData);// APC ť��� ������忡�� �񵿱��� ������ ����
		VOID CleanUp_APC();

		
	}
}

extern "C" VOID NTAPI KernelApcCleanup(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);

#endif