#include "ProcessUtil.hpp"
#include "API.hpp"

namespace EDR
{
	namespace Util
	{
		namespace Process
		{
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

					while (ZwQueryInformationProcess(ProcessHandle, (SYSTEM_INFORMATION_CLASS)ProcessImageFileName, get_buffer, process_FULL_NAME_info_len, &process_FULL_NAME_info_len) == STATUS_INFO_LENGTH_MISMATCH) {
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