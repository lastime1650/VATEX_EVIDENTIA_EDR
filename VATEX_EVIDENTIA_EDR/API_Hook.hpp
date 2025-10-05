#ifndef API_CALLS_EVENT_HPP
#define API_CALLS_EVENT_HPP

#include "util.hpp"
#include "API.hpp"

#include "PE_Logic.hpp"

namespace EDR
{
	namespace APIHooking
	{
		//namespace resource
		//{
		//	UNICODE_STRING HookDllPath;
		//}

		BOOLEAN Set_hooking(HANDLE ProcessId);

		namespace Handler
		{
			extern "C" VOID API_Hooking_HANDLER(HANDLE procesid)
			{
				
				// test 1초 대기
				LARGE_INTEGER interval;
				interval.QuadPart = -10 * 1000 * 1000;
				KeDelayExecutionThread(KernelMode, FALSE, &interval);

				debug_log("Set_hooking -> %d\n", Set_hooking(procesid));
			}
		}

		BOOLEAN Set_hooking(
			HANDLE ProcessId
		)
		{
			//debug_break();

			/*
				64bit 또는 32bit 확인하여 알맞는 dll 후킹시도.
			*/
			PEPROCESS eprocess = NULL;
			if( !NT_SUCCESS( PsLookupProcessByProcessId(ProcessId, &eprocess) ) )
				return FALSE;

			// test, 32bit 프로세스면 FALSE
			BOOLEAN is_32bit = (PsGetProcessWow64Process(eprocess) != NULL) ? TRUE : FALSE;
			ObDereferenceObject(eprocess);

			if (is_32bit)
				return FALSE;
			

			// test
			EDR::Util::Shared::API_HOOK::HookDllPath = "C:\\Users\\Administrator\\Desktop\\HookDll.dll";

			if (!EDR::Util::Shared::API_HOOK::HookDllPath)
				return FALSE;

			// 1. Target Process의 LoadLibraryA API VirtualAddress 얻기

			PUCHAR kernel32_DLLBASE = NULL;
			PUCHAR TargetProcess_LoadLibraryA_VirtualAddress = NULL;
			NTSTATUS status = EDR::Util::PE::Dll_API_Address_Search(
				ProcessId,
				L"kernel32.dll", // Dll Name
				"LoadLibraryA", // API Name
				&kernel32_DLLBASE,
				&TargetProcess_LoadLibraryA_VirtualAddress
			);
			if (!NT_SUCCESS(status))
				return FALSE;

			// 2. LoadLibraryA Arguments Dll String Data Allocated to Target Process !~

			HANDLE TargetProcessHandle = NULL;
			status = EDR::Util::Process::Handle::LookupProcessHandlebyProcessId(ProcessId, &TargetProcessHandle);
			if (!NT_SUCCESS(status) || !TargetProcessHandle)
				return FALSE;

			// 가상 공간에 Hook할 절대경로만큼 공간할당 후 Copy
			PVOID Allocated_VirtualAdress = NULL;
			ULONG64 HookDllPath_Size = (strlen(EDR::Util::Shared::API_HOOK::HookDllPath) + 1);
			SIZE_T Allocate_Size = HookDllPath_Size;
			status = EDR::Util::UserSpace::Memory::AllocateMemory(
				TargetProcessHandle,
				&Allocated_VirtualAdress,
				&Allocate_Size
			);
			if (!NT_SUCCESS(status))
			{
				EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(TargetProcessHandle);
				return FALSE;
			}

			// copy
			if (!EDR::Util::UserSpace::Memory::Copy(ProcessId, Allocated_VirtualAdress, (PVOID)EDR::Util::Shared::API_HOOK::HookDllPath, HookDllPath_Size))
			{

				EDR::Util::UserSpace::Memory::FreeMemory(TargetProcessHandle, Allocated_VirtualAdress, Allocate_Size);

				EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(TargetProcessHandle);
				
				return FALSE;
			}


			// 커널에서 타겟 프로세스에 Thread 생성
			// Dll Inject START
			status = RtlCreateUserThread(
				TargetProcessHandle, // Target Process REAL Handle
				NULL, // Security Descriptor
				FALSE, // Create Suspended
				0, // ZeroBits
				0, // Stack Zero
				0, // Stack Zero
				TargetProcess_LoadLibraryA_VirtualAddress, // LoadLibraryA Address
				Allocated_VirtualAdress, // Dll Path to Inject
				NULL, // Thread Handle ( NULL )
				NULL // Client ID ( NULL )

			);
			if (!NT_SUCCESS(status))
			{
				debug_log("RtlCreateUserThread Failed -> %p \n", status);
				EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(TargetProcessHandle);
				return FALSE;
			}
				

			EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(TargetProcessHandle);
			return TRUE;
		}


		
	}
}

#endif