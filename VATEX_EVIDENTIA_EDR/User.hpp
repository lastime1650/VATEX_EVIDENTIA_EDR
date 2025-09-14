#ifndef USER_H
#define USER_H

#include <ntifs.h>

namespace EDR
{
	namespace Util
	{
		namespace UserSpace
		{
			namespace Memory
			{
				NTSTATUS AllocateMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* DataSize);
				VOID FreeMemory(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T DataSize);
			
				BOOLEAN Copy(HANDLE ProcessId, PVOID User_Dest, PVOID Kernel_Src, SIZE_T Size);
			
			}
		}
	}
}

#endif