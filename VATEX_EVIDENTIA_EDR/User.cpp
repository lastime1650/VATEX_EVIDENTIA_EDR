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
                    KAPC_STATE state;
                    PMDL mdl = NULL;
                    PVOID MappedSystemVa = NULL;
                    BOOLEAN bResult = FALSE;

                    // 1. 프로세스 참조 획득
                    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
                    {
                        return FALSE;
                    }

                    // 2. 해당 프로세스 컨텍스트로 진입 (MDL 생성을 위해 필수)
                    KeStackAttachProcess(Process, &state);

                    __try
                    {
                        // 3. MDL 할당 (User_Dest 주소에 대한 서술자 생성)
                        mdl = IoAllocateMdl(User_Dest, (ULONG)Size, FALSE, FALSE, NULL);
                        if (!mdl)
                        {
                            // 메모리 부족 등으로 MDL 생성 실패
                            __leave;
                        }

                        // 4. 페이지 고정 (Probing & Locking)
                        // 유저 메모리가 유효한지 검사하고, 물리 메모리에 고정시킴 (Paging 방지)
                        // 이 함수는 실패 시 예외를 던지므로 반드시 __try/__except 내부에 있어야 함
                        MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        // 유저가 메모리를 해제했거나 접근 권한이 없는 경우
                        if (mdl)
                        {
                            IoFreeMdl(mdl);
                            mdl = NULL;
                        }
                        KeUnstackDetachProcess(&state);
                        ObDereferenceObject(Process);
                        return FALSE;
                    }

                    // 5. 커널 공간으로 매핑 (선택 사항이지만 안전을 위해 권장)
                    // Locked된 페이지를 커널 가상 주소(SystemSpace)로 매핑합니다.
                    // 이렇게 하면 User_Dest 주소가 아닌, 커널 주소를 통해 쓰기 때문에 컨텍스트 제약이 사라집니다.
                    MappedSystemVa = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

                    if (!MappedSystemVa)
                    {
                        MmUnlockPages(mdl);
                        IoFreeMdl(mdl);
                        KeUnstackDetachProcess(&state);
                        ObDereferenceObject(Process);
                        return FALSE;
                    }

                    // 6. 메모리 복사 수행
                    // 이제 MappedSystemVa는 커널 주소이므로 안전하게 복사 가능
                    __try
                    {
                        RtlCopyMemory(MappedSystemVa, Kernel_Src, Size);
                        bResult = TRUE;
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        bResult = FALSE;
                    }

                    // 7. 정리 (매핑 해제 -> 잠금 해제 -> MDL 해제)
                    MmUnmapLockedPages(MappedSystemVa, mdl);
                    MmUnlockPages(mdl);
                    IoFreeMdl(mdl);

                    // 8. 프로세스 디태치 및 참조 해제
                    KeUnstackDetachProcess(&state);
                    ObDereferenceObject(Process);

                    return bResult;
                }
			}
		}
	}
}