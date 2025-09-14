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
				return FALSE; // 이미 등록된 경우변경금지. ( 드라이버 재등록 및 재부팅 요구됨 )

			if (!NT_SUCCESS(PsLookupThreadByThreadId(USER_ThreadID, &resource::USER_Thread)))
				return FALSE;

			resource::USER_APC_HANDLER = (PKNORMAL_ROUTINE)USER_APC_Handler;

			resource::is_working_apc = TRUE;
			return TRUE;
		}

		BOOLEAN ApcToUser(ULONG64 cmd, PVOID UserAllocatedData, ULONG64 DataSize)// APC 큐기반 유저모드에게 비동기적 데이터 전송
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
				(PVOID)cmd // 유저모드 APC 콜백함수에 전달할 것 ( NornalContext )  -> Type
			);

			if (!KeInsertQueueApc(
				Response_APC,
				UserAllocatedData, // Data 주소 ( Argument 1 )
				(PVOID)DataSize, // Data 사이즈 ( Argument 2 )
				0
			)
			) {
				ExFreePoolWithTag(Response_APC, APC_ALLOC_TAG);
				return FALSE;
			}
			else {
				/* KernelApcCleanup 루틴이 해제한다. */
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

	// KeInsertQueueApc가 사용한 APC 객체를 해제합니다.
	ExFreePoolWithTag(Apc, APC_ALLOC_TAG);
}
