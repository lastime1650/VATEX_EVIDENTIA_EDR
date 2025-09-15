#ifndef OB_REGISETERS_CALLBACK_H
#define OB_REGISETERS_CALLBACK_H

#include "util.hpp"


#define PROCESS_CREATE_PROCESS      (0x0080)  // 프로세스의 새 자식 프로세스를 만듭니다.
#define PROCESS_CREATE_THREAD       (0x0002)  // 프로세스의 컨텍스트에서 새 스레드를 만듭니다.
#define PROCESS_DUP_HANDLE          (0x0040)  // 사용자 모드 DuplicateHandle 루틴을 호출하는 등 프로세스 컨텍스트에서 핸들을 복제합니다.
#define PROCESS_SET_QUOTA           (0x0100)  // 사용자 모드 SetProcessWorkingSetSize 루틴을 호출하는 등 프로세스의 작업 집합 크기를 설정합니다.
#define PROCESS_SET_INFORMATION     (0x0200)  // 사용자 모드 SetPriorityClass 루틴을 호출하는 등의 프로세스 설정을 수정합니다.
#define PROCESS_SUSPEND_RESUME      (0x0800)  // 프로세스를 일시 중단하거나 다시 시작합니다.
#define PROCESS_TERMINATE           (0x0001)  // 사용자 모드 TerminateProcess 루틴을 호출하는 등의 프로세스를 종료합니다.
#define PROCESS_VM_OPERATION        (0x0008)  // 사용자 모드 WriteProcessMemory 및 VirtualProtectEx 루틴을 호출하는 등 프로세스의 주소 공간을 수정합니다.
#define PROCESS_VM_WRITE            (0x0020)  // 사용자 모드 WriteProcessMemory 루틴을 호출하는 등 프로세스의 주소 공간에 씁니다.

#define ObRegisterCallbacks_Altitude L"16501"

namespace EDR
{
	namespace ObRegisterCallback
	{
		namespace Handler
		{
			extern "C" OB_PREOP_CALLBACK_STATUS PreOperationCallback(
				_In_ PVOID RegistrationContext,
				_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
			);
		}
		NTSTATUS Load_ObRegisterCallbacks();
		VOID CleanUp_ObRegisterCallbacks();
	}
}

#endif