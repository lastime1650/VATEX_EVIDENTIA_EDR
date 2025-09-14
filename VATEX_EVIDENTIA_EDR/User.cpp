#include "User.hpp"

namespace EDR
{
	namespace Util
	{
		namespace UserSpace
		{
			namespace Memory
			{
				NTSTATUS AllocateMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* DataSize)
				{
					if (!ProcessHandle || !BaseAddress || !DataSize || !*DataSize)
						return STATUS_INVALID_PARAMETER;

					PVOID tmp_BaseAddress = NULL;
					SIZE_T tmp_DataSize = *DataSize;

					NTSTATUS status = ZwAllocateVirtualMemory(
						ProcessHandle,
						&tmp_BaseAddress,
						0,
						&tmp_DataSize,
						MEM_COMMIT,
						PAGE_READWRITE
					);

					if(!NT_SUCCESS(status))
					{
						*BaseAddress = NULL;
					}
					else
					{
						*BaseAddress = tmp_BaseAddress;
						*DataSize = tmp_DataSize;

					}

					return status;
				}

				VOID FreeMemory(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T DataSize)
				{
					if (!ProcessHandle)
						return;

					PVOID base = BaseAddress;
					SIZE_T size = DataSize;

					ZwFreeVirtualMemory(
						ProcessHandle,
						&base,
						&size,
						MEM_RELEASE
					);

					return;

				}

				BOOLEAN Copy(HANDLE ProcessId, PVOID User_Dest, PVOID Kernel_Src, SIZE_T Size)
				{
					PEPROCESS Process = NULL;
					if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
						return FALSE;

					KAPC_STATE state;
					KeStackAttachProcess(Process, &state);

					RtlCopyMemory(
						User_Dest,
						Kernel_Src,
						Size
					);

					KeUnstackDetachProcess(&state);

					ObDereferenceObject(Process);

					return TRUE;
				}
			}
		}
	}
}