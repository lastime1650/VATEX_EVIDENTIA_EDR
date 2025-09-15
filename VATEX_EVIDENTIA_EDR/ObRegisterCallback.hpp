#ifndef OB_REGISETERS_CALLBACK_H
#define OB_REGISETERS_CALLBACK_H

#include "util.hpp"


#define PROCESS_CREATE_PROCESS      (0x0080)  // ���μ����� �� �ڽ� ���μ����� ����ϴ�.
#define PROCESS_CREATE_THREAD       (0x0002)  // ���μ����� ���ؽ�Ʈ���� �� �����带 ����ϴ�.
#define PROCESS_DUP_HANDLE          (0x0040)  // ����� ��� DuplicateHandle ��ƾ�� ȣ���ϴ� �� ���μ��� ���ؽ�Ʈ���� �ڵ��� �����մϴ�.
#define PROCESS_SET_QUOTA           (0x0100)  // ����� ��� SetProcessWorkingSetSize ��ƾ�� ȣ���ϴ� �� ���μ����� �۾� ���� ũ�⸦ �����մϴ�.
#define PROCESS_SET_INFORMATION     (0x0200)  // ����� ��� SetPriorityClass ��ƾ�� ȣ���ϴ� ���� ���μ��� ������ �����մϴ�.
#define PROCESS_SUSPEND_RESUME      (0x0800)  // ���μ����� �Ͻ� �ߴ��ϰų� �ٽ� �����մϴ�.
#define PROCESS_TERMINATE           (0x0001)  // ����� ��� TerminateProcess ��ƾ�� ȣ���ϴ� ���� ���μ����� �����մϴ�.
#define PROCESS_VM_OPERATION        (0x0008)  // ����� ��� WriteProcessMemory �� VirtualProtectEx ��ƾ�� ȣ���ϴ� �� ���μ����� �ּ� ������ �����մϴ�.
#define PROCESS_VM_WRITE            (0x0020)  // ����� ��� WriteProcessMemory ��ƾ�� ȣ���ϴ� �� ���μ����� �ּ� ������ ���ϴ�.

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