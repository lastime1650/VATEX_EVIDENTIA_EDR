#include "ProcessUtil.hpp"
#include "API.hpp"


namespace EDR
{
	namespace Util
	{
		namespace Process
		{
			HANDLE GetParentProcess(HANDLE ProcessId)
			{
				PAGED_CODE();
				if (!ProcessId)
					return NULL;

				HANDLE ParentProcessId = NULL;
				HANDLE hProcess = NULL;
				OBJECT_ATTRIBUTES objAttr;
				CLIENT_ID clientId;
				PROCESS_BASIC_INFORMATION pbi;
				ULONG returnLength;

				InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
				clientId.UniqueProcess = (HANDLE)(ULONG_PTR)ProcessId;
				clientId.UniqueThread = NULL;

				NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION, &objAttr, &clientId);
				if (!NT_SUCCESS(status)) {
					// 프로세스가 이미 종료되었거나 접근 권한이 없는 경우
					return NULL;
				}

				__try {
					status = ZwQueryInformationProcess(
						hProcess,
						ProcessBasicInformation,   // PROCESS_BASIC_INFORMATION 얻기
						&pbi,
						sizeof(pbi),
						&returnLength
					);

					if (NT_SUCCESS(status)) {
						ParentProcessId = (HANDLE)((ULONG_PTR)pbi.InheritedFromUniqueProcessId);
					}
				}
				__finally {
					if (hProcess != NULL) {
						ZwClose(hProcess);
					}
				}

				return ParentProcessId;
			}

			namespace Terminate
			{
				#define QueryProcessTag 'QPAL'
				NTSTATUS TerminateProcess(HANDLE ProcessId)
				{
					if (!ProcessId)
						return STATUS_INVALID_PARAMETER_1;

					ULONG bufferSize = 0; // Initial buffer size
					PUCHAR buffer = NULL;
					while (ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize) == STATUS_INFO_LENGTH_MISMATCH) {
						if (buffer == NULL) {
							buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, QueryProcessTag); // QueRyProceSs
							if (buffer == NULL) {
								return STATUS_INSUFFICIENT_RESOURCES;
							}
						}
					}
					PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
					while (processInfo) {
						if (processInfo->UniqueProcessId == ProcessId) {

							HANDLE ProcessHandle = NULL;
							Handle::LookupProcessHandlebyProcessId(ProcessId, &ProcessHandle);
							if (ProcessHandle)
							{
								ZwTerminateProcess(ProcessHandle, STATUS_SUCCESS);
								Handle::ReleaseLookupProcessHandlebyProcessId(ProcessHandle);
								ExFreePoolWithTag(buffer, QueryProcessTag);
								return STATUS_SUCCESS;
							}
							
							
						}

						processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
					}

					ExFreePoolWithTag(buffer, QueryProcessTag);

					return STATUS_UNSUCCESSFUL;
				}
			}
			namespace Handle
			{
				NTSTATUS LookupProcessHandlebyProcessId(HANDLE ProcessId, HANDLE* ProcessHandle)
				{
					if (!ProcessHandle)
						return STATUS_INVALID_PARAMETER;

					NTSTATUS status = STATUS_SUCCESS;

					PEPROCESS eprocess = NULL;
					status = PsLookupProcessByProcessId(ProcessId, &eprocess);
					if (!NT_SUCCESS(status)) {
						return status; // Failed to get process object
					}

					status = ObOpenObjectByPointer(
						eprocess,
						OBJ_KERNEL_HANDLE,
						NULL,
						PROCESS_ALL_ACCESS, // Adjust access rights as needed
						*PsProcessType,
						KernelMode,
						ProcessHandle
					);
					if (!NT_SUCCESS(status)) {
						*ProcessHandle = NULL;
						ObDereferenceObject(eprocess);
						return status; // Failed to get process object
					}
					ObDereferenceObject(eprocess);
					return STATUS_SUCCESS;

				}

				VOID ReleaseLookupProcessHandlebyProcessId(HANDLE ProcessHandle)
				{
					if (ProcessHandle)
						ZwClose(ProcessHandle);
				}
			}

			namespace ImagePath
			{
				NTSTATUS LookupProcessAbsoluteImagePathbyProcessHandle(HANDLE ProcessHandle, PUNICODE_STRING* output_unicode)
				{
					if (!output_unicode)
						return STATUS_INVALID_PARAMETER;


					PVOID get_buffer = NULL;
					ULONG process_FULL_NAME_info_len = 0;

					while (ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, get_buffer, process_FULL_NAME_info_len, &process_FULL_NAME_info_len) == STATUS_INFO_LENGTH_MISMATCH) {
						if (get_buffer != NULL) {
							break;
						}
						get_buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, process_FULL_NAME_info_len, ImagePath_ALLOC_TAG);
					}

					if (get_buffer == NULL) {
						return STATUS_MEMORY_NOT_ALLOCATED;
					}

					*output_unicode = (PUNICODE_STRING)get_buffer;

					return STATUS_SUCCESS;
				}
				VOID ReleaseLookupProcessAbsoluteImagePathbyProcessHandle(PUNICODE_STRING unicode)
				{
					ExFreePoolWithTag(unicode, ImagePath_ALLOC_TAG);
				}
			}

		}
	}
}