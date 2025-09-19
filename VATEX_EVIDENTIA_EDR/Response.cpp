#include "Response.hpp"

// 차단 조치 

#define POOL_TAG 'hsTB'
namespace EDR
{
    namespace Response
    {
        
        namespace HashTable {

            // 전역 데이터 (cpp 파일에 정의)
            RTL_GENERIC_TABLE g_BlockTable;
            EX_PUSH_LOCK g_TableLock;

            // 콜백 루틴 선언
            extern "C" RTL_GENERIC_COMPARE_RESULTS NTAPI CompareRoutine(
                _In_ RTL_GENERIC_TABLE* Table,
                _In_ PVOID FirstStruct,
                _In_ PVOID SecondStruct
            )
            {
                /*
                    [Return]

                        < 비교 기준 > 
                            ByteCompare( strcmp() ) 에서 한차례식 비교할 때의 반환값을 기준으로 해시테이블 값 탐색 

                        1. GenericLessThan ( 찾는 Byte를 비교헀을 때 작은 경우 )
                        2. GenericGreaterThan ( 찾는 Byte를 비교헀을 때 큰 경우 )
                        3. GenericEqual ( 찾으려는 데이터와 Type 2개가 완전히 일치 )
                */
                UNREFERENCED_PARAMETER(Table);
                auto entry1 = static_cast<Struct::PBLOCK_ENTRY>(FirstStruct);
                auto entry2 = static_cast<Struct::PBLOCK_ENTRY>(SecondStruct);

                // 1. 타입 비교
                if (entry1->Type < entry2->Type) return GenericLessThan;
                if (entry1->Type > entry2->Type) return GenericGreaterThan;

                // 2. 타입이 같으면 데이터 비교
                switch (entry1->Type) {
                    case Enum::BlockTypeFileSha256:
                    {

                        // 해시가 같으면 파일 크기로 2차 비교
                        if (entry1->Data.File.FileSize < entry2->Data.File.FileSize) return GenericLessThan;
                        if (entry1->Data.File.FileSize > entry2->Data.File.FileSize) return GenericGreaterThan;

                        // 해시 문자열로 1차 비교
                        int hashResult = strcmp((const char*)entry1->Data.File.FileHash, (const char*)entry2->Data.File.FileHash);
                        if (hashResult < 0) return GenericLessThan;
                        if (hashResult > 0) return GenericGreaterThan;

                        return GenericEqual;
                    }
                    case Enum::BlockTypeIpAddress:
                    {
                        int ipResult = strcmp(entry1->Data.IpAddress, entry2->Data.IpAddress);
                        if (ipResult < 0) return GenericLessThan;
                        if (ipResult > 0) return GenericGreaterThan;
                        return GenericEqual;
                    }
                }
                return GenericEqual;
            }

            extern "C" PVOID NTAPI AllocateRoutine(
                _In_ RTL_GENERIC_TABLE* Table,
                _In_ CLONG ByteSize
            ) {
                return ExAllocatePool2(POOL_FLAG_NON_PAGED, ByteSize, POOL_TAG);
            }

            extern "C" VOID NTAPI FreeRoutine(
                _In_ RTL_GENERIC_TABLE* Table,
                _In_ PVOID Buffer
            ) {
                ExFreePoolWithTag(Buffer, POOL_TAG);
            }

            // 초기화 및 해제 함수
            NTSTATUS Initialize()
            {
                ExInitializePushLock(&g_TableLock);
                RtlInitializeGenericTable(
                    &g_BlockTable,
                    CompareRoutine,
                    AllocateRoutine,
                    FreeRoutine,
                    NULL
                );
                return STATUS_SUCCESS;
            }
            BOOLEAN CleanUp()
            {
                if (KeGetCurrentIrql() >= APC_LEVEL)
                    return FALSE;

                ExAcquirePushLockExclusive(&g_TableLock);
                for (PVOID pElement = RtlEnumerateGenericTable(&g_BlockTable, TRUE);
                    pElement != nullptr;
                    pElement = RtlEnumerateGenericTable(&g_BlockTable, TRUE))
                {
                    // GetElement 후 바로 Delete를 하면 불안정할 수 있으므로
                    // 키를 복사한 후 Delete 하는 것이 더 안전함.
                    // 여기서는 간단한 예시로 바로 삭제.
                    RtlDeleteElementGenericTable(&g_BlockTable, pElement);
                }
                ExReleasePushLockExclusive(&g_TableLock);
                return TRUE;
            }

            // 데이터 조작 함수 (외부 인터페이스)
            NTSTATUS AddFileBlock(
                _In_ const CHAR* FileHash,
                _In_ ULONG64 FileSize,
                _In_ Enum::ResponseAction Action
            )
            {
                if (FileHash == nullptr) return STATUS_INVALID_PARAMETER;

                Struct::BLOCK_ENTRY newEntry;
                RtlZeroMemory(&newEntry, sizeof(Struct::BLOCK_ENTRY));

                newEntry.Type = Enum::BlockTypeFileSha256;
                newEntry.Action = Action;
                newEntry.Data.File.FileSize = FileSize;
                NTSTATUS status = RtlStringCchCopyA((PSTR)newEntry.Data.File.FileHash, sizeof(newEntry.Data.File.FileHash), FileHash);
                if (!NT_SUCCESS(status)) return status;

                ExAcquirePushLockExclusive(&g_TableLock);

                BOOLEAN isNewElement = FALSE;
                PVOID insertedEntry = RtlInsertElementGenericTable(&g_BlockTable, &newEntry, sizeof(Struct::BLOCK_ENTRY), &isNewElement);

                ExReleasePushLockExclusive(&g_TableLock);

                return (insertedEntry != nullptr) ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS AddIpBlock(
                _In_ const CHAR* IpAddress,
                _In_ Enum::ResponseAction Action
            )
            {
                if (IpAddress == nullptr) return STATUS_INVALID_PARAMETER;

                Struct::BLOCK_ENTRY newEntry;
                RtlZeroMemory(&newEntry, sizeof(Struct::BLOCK_ENTRY));

                newEntry.Type = Enum::BlockTypeFileSha256;
                newEntry.Action = Action;
                NTSTATUS status = RtlStringCchCopyA((PSTR)newEntry.Data.IpAddress, sizeof(newEntry.Data.IpAddress), IpAddress);
                if (!NT_SUCCESS(status)) return status;

                ExAcquirePushLockExclusive(&g_TableLock);

                BOOLEAN isNewElement = FALSE;
                PVOID insertedEntry = RtlInsertElementGenericTable(&g_BlockTable, &newEntry, sizeof(Struct::BLOCK_ENTRY), &isNewElement);

                ExReleasePushLockExclusive(&g_TableLock);

                return (insertedEntry != nullptr) ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
            }

            BOOLEAN RemoveFileBlock(
                _In_ const CHAR* FileHash,
                _In_ ULONG64 FileSize
            )
            {
                if (FileHash == nullptr) return FALSE;

                Struct::BLOCK_ENTRY entryToRemove;
                RtlZeroMemory(&entryToRemove, sizeof(Struct::BLOCK_ENTRY));

                // [수정] 오타 수정
                entryToRemove.Type = Enum::BlockTypeFileSha256;
                RtlStringCchCopyA((PSTR)entryToRemove.Data.File.FileHash, sizeof(entryToRemove.Data.File.FileHash), FileHash);

                ExAcquirePushLockExclusive(&g_TableLock);

                BOOLEAN wasDeleted = RtlDeleteElementGenericTable(&g_BlockTable, &entryToRemove);

                ExReleasePushLockExclusive(&g_TableLock);

                return wasDeleted;
            }

            BOOLEAN RemoveIpBlock(
                _In_ const CHAR* IpAddress
            )
            {
                if (IpAddress == nullptr) return FALSE;

                Struct::BLOCK_ENTRY entryToRemove;
                RtlZeroMemory(&entryToRemove, sizeof(Struct::BLOCK_ENTRY));

                // [수정] 오타 수정
                entryToRemove.Type = Enum::BlockTypeIpAddress;
                RtlStringCchCopyA(entryToRemove.Data.IpAddress, sizeof(entryToRemove.Data.IpAddress), IpAddress);

                ExAcquirePushLockExclusive(&g_TableLock);

                BOOLEAN wasDeleted = RtlDeleteElementGenericTable(&g_BlockTable, &entryToRemove);

                ExReleasePushLockExclusive(&g_TableLock);

                return wasDeleted;
            }

            // 조회 함수 (가장 핵심)
            Enum::ResponseAction CheckFileAction(
                _In_ const CHAR* FileHash,
                _In_ ULONG64 FileSize
            )
            {

                Struct::BLOCK_ENTRY lookupEntry;
                RtlZeroMemory(&lookupEntry, sizeof(Struct::BLOCK_ENTRY));

                lookupEntry.Type = Enum::BlockTypeFileSha256;
                lookupEntry.Data.File.FileSize = FileSize;
                RtlStringCchCopyA((PSTR)lookupEntry.Data.File.FileHash, sizeof(lookupEntry.Data.File.FileHash), FileHash);

                ExAcquirePushLockExclusive(&g_TableLock);
                Struct::PBLOCK_ENTRY foundEntry = static_cast<Struct::PBLOCK_ENTRY>(
                    RtlLookupElementGenericTable(&g_BlockTable, &lookupEntry)
                    );
                ExReleasePushLockExclusive(&g_TableLock);

                if (foundEntry) {
                    return foundEntry->Action;
                }
                else
                {
                    return Enum::Allow; // 찾지 못하면 기본값 Allow
                }

                
            }

            Enum::ResponseAction CheckIpAction(
                _In_ const CHAR* IpAddress
            )
            {
                if( KeGetCurrentIrql() >= DISPATCH_LEVEL) // ExAcquireFastMutex() 는 <= APC_LEVEL에서 작동
                    return Enum::Allow;

                Struct::BLOCK_ENTRY lookupEntry;
                RtlZeroMemory(&lookupEntry, sizeof(Struct::BLOCK_ENTRY));

                lookupEntry.Type = Enum::BlockTypeIpAddress;
                RtlStringCchCopyA(lookupEntry.Data.IpAddress, sizeof(lookupEntry.Data.IpAddress), IpAddress);

                ExAcquirePushLockExclusive(&g_TableLock);
                Struct::PBLOCK_ENTRY foundEntry = static_cast<Struct::PBLOCK_ENTRY>(
                    RtlLookupElementGenericTable(&g_BlockTable, &lookupEntry)
                    );
                ExReleasePushLockExclusive(&g_TableLock);

                if (foundEntry) {
                    return foundEntry->Action;
                }
                else
                {
                    return Enum::Allow; // 찾지 못하면 기본값 Allow
                }
            }

        }
    }
}