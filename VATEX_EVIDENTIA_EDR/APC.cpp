#pragma warning (disable : 4996)
#include "APC.hpp"


namespace EDR
{
	namespace APC
	{
		namespace resource
		{
			PETHREAD USER_Thread = NULL;
			PKNORMAL_ROUTINE USER_APC_HANDLER = NULL;

			BOOLEAN is_working_apc = FALSE;

			PFAST_MUTEX mutex = NULL;
		}


		BOOLEAN INITIALIZE_APC(HANDLE USER_ThreadID, PVOID USER_APC_Handler)
		{

			if (resource::USER_Thread || resource::is_working_apc || resource::mutex)
				return FALSE; // �̹� ��ϵ� ��캯�����. ( ����̹� ���� �� ����� �䱸�� )

			if (!NT_SUCCESS(PsLookupThreadByThreadId(USER_ThreadID, &resource::USER_Thread)))
				return FALSE;

			resource::USER_APC_HANDLER = (PKNORMAL_ROUTINE)USER_APC_Handler;

			resource::is_working_apc = TRUE;
			return TRUE;
		}

		BOOLEAN ApcToUser(ULONG64 cmd, PVOID UserAllocatedData, ULONG64 DataSize)// APC ť��� ������忡�� �񵿱��� ������ ����
		{
			if (!resource::USER_Thread || !resource::is_working_apc)
				return FALSE;

			PKAPC Response_APC = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), APC_ALLOC_TAG);
			if (!Response_APC)
			{
				return FALSE;
			}

			KeInitializeApc(
				Response_APC,
				resource::USER_Thread,
				OriginalApcEnvironment,
				KernelApcCleanup,
				NULL,
				(PKNORMAL_ROUTINE)resource::USER_APC_HANDLER, // USER ADDRESS CALLBACK ! 
				UserMode,
				(PVOID)cmd // ������� APC �ݹ��Լ��� ������ �� ( NornalContext )  -> Type
			);

			if (!KeInsertQueueApc(
				Response_APC,
				UserAllocatedData, // Data �ּ� ( Argument 1 )
				(PVOID)DataSize, // Data ������ ( Argument 2 )
				0
			)
			) {
				ExFreePoolWithTag(Response_APC, APC_ALLOC_TAG);
				return FALSE;
			}
			else {
				/* KernelApcCleanup ��ƾ�� �����Ѵ�. */
			}

			return TRUE;

		}

		VOID CleanUp_APC()
		{
			if (resource::USER_Thread)
			{
				ObfDereferenceObject(resource::USER_Thread);
				resource::USER_APC_HANDLER = NULL;
				resource::is_working_apc = FALSE;
			}
				
		}


	}
}



extern "C" VOID NTAPI KernelApcCleanup(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	// KeInsertQueueApc�� ����� APC ��ü�� �����մϴ�.
	ExFreePoolWithTag(Apc, APC_ALLOC_TAG);
}
