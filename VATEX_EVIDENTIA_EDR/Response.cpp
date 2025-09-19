#include "Response.hpp"

// ���� ��ġ 

#define POOL_TAG 'hsTB'
namespace EDR
{
    namespace Response
    {
        
        namespace HashTable {

            // ���� ������ (cpp ���Ͽ� ����)
            RTL_GENERIC_TABLE g_BlockTable;
            EX_PUSH_LOCK g_TableLock;

            // �ݹ� ��ƾ ����
            extern "C" RTL_GENERIC_COMPARE_RESULTS NTAPI CompareRoutine(
                _In_ RTL_GENERIC_TABLE* Table,
                _In_ PVOID FirstStruct,
                _In_ PVOID SecondStruct
            )
            {
                /*
                    [Return]

                        < �� ���� > 
                            ByteCompare( strcmp() ) ���� �����ʽ� ���� ���� ��ȯ���� �������� �ؽ����̺� �� Ž�� 

                        1. GenericLessThan ( ã�� Byte�� ������ �� ���� ��� )
                        2. GenericGreaterThan ( ã�� Byte�� ������ �� ū ��� )
                        3. GenericEqual ( ã������ �����Ϳ� Type 2���� ������ ��ġ )
                */
                UNREFERENCED_PARAMETER(Table);
                auto entry1 = static_cast<Struct::PBLOCK_ENTRY>(FirstStruct);
                auto entry2 = static_cast<Struct::PBLOCK_ENTRY>(SecondStruct);

                // 1. Ÿ�� ��
                if (entry1->Type < entry2->Type) return GenericLessThan;
                if (entry1->Type > entry2->Type) return GenericGreaterThan;

                // 2. Ÿ���� ������ ������ ��
                switch (entry1->Type) {
                    case Enum::BlockTypeFileSha256:
                    {

                        // �ؽð� ������ ���� ũ��� 2�� ��
                        if (entry1->Data.File.FileSize < entry2->Data.File.FileSize) return GenericLessThan;
                        if (entry1->Data.File.FileSize > entry2->Data.File.FileSize) return GenericGreaterThan;

                        // �ؽ� ���ڿ��� 1�� ��
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

            // �ʱ�ȭ �� ���� �Լ�
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
                    // GetElement �� �ٷ� Delete�� �ϸ� �Ҿ����� �� �����Ƿ�
                    // Ű�� ������ �� Delete �ϴ� ���� �� ������.
                    // ���⼭�� ������ ���÷� �ٷ� ����.
                    RtlDeleteElementGenericTable(&g_BlockTable, pElement);
                }
                ExReleasePushLockExclusive(&g_TableLock);
                return TRUE;
            }

            // ������ ���� �Լ� (�ܺ� �������̽�)
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

                // [����] ��Ÿ ����
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

                // [����] ��Ÿ ����
                entryToRemove.Type = Enum::BlockTypeIpAddress;
                RtlStringCchCopyA(entryToRemove.Data.IpAddress, sizeof(entryToRemove.Data.IpAddress), IpAddress);

                ExAcquirePushLockExclusive(&g_TableLock);

                BOOLEAN wasDeleted = RtlDeleteElementGenericTable(&g_BlockTable, &entryToRemove);

                ExReleasePushLockExclusive(&g_TableLock);

                return wasDeleted;
            }

            // ��ȸ �Լ� (���� �ٽ�)
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
                    return Enum::Allow; // ã�� ���ϸ� �⺻�� Allow
                }

                
            }

            Enum::ResponseAction CheckIpAction(
                _In_ const CHAR* IpAddress
            )
            {
                if( KeGetCurrentIrql() >= DISPATCH_LEVEL) // ExAcquireFastMutex() �� <= APC_LEVEL���� �۵�
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
                    return Enum::Allow; // ã�� ���ϸ� �⺻�� Allow
                }
            }

        }
    }
}