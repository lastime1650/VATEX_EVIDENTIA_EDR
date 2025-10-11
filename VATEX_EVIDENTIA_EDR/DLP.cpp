#include "DLP.hpp"

namespace DLP
{
	namespace resource
	{
		namespace hashMap
		{
            RTL_GENERIC_TABLE g_DlpTable;
            EX_PUSH_LOCK g_DlpTableLock;

            // FileReferenceNumber ���� ���������� �������̸� �׷����Ѵ�. (�� ������ )
            RTL_GENERIC_COMPARE_RESULTS NTAPI CompareRoutine(
                _In_ RTL_GENERIC_TABLE* Table,
                _In_ PVOID FirstStruct,
                _In_ PVOID SecondStruct
            ) {
                auto f1 = static_cast<PDLP_TABLE_ENTRY>(FirstStruct);
                auto f2 = static_cast<PDLP_TABLE_ENTRY>(SecondStruct);

                if (f1->FileReferenceNumber < f2->FileReferenceNumber)
                    return GenericLessThan;
                else if (f1->FileReferenceNumber > f2->FileReferenceNumber)
                    return GenericGreaterThan;
                return GenericEqual;
            }

            PVOID NTAPI AllocateRoutine(_In_ RTL_GENERIC_TABLE* Table, _In_ CLONG ByteSize) {
                UNREFERENCED_PARAMETER(Table);
                return ExAllocatePool2(POOL_FLAG_NON_PAGED, ByteSize, 'LDPD');
            }

            VOID NTAPI FreeRoutine(_In_ RTL_GENERIC_TABLE* Table, _In_ PVOID Buffer) {
                UNREFERENCED_PARAMETER(Table);
                ExFreePoolWithTag(Buffer, 'LDPD');
            }

            NTSTATUS Initialize_DLP_HashMap() {
                ExInitializePushLock(&g_DlpTableLock);
                RtlInitializeGenericTable(
                    &g_DlpTable,
                    CompareRoutine,
                    AllocateRoutine,
                    FreeRoutine,
                    nullptr
                );
                return STATUS_SUCCESS;
            }

            BOOLEAN InsertOrUpdate(PDLP_Info Info) {
                if (!Info) return FALSE;

                DLP_TABLE_ENTRY entryToInsert = { Info->FILE.FileReferenceNumber, Info };
                BOOLEAN newElement = FALSE;

                ExAcquirePushLockExclusive(&g_DlpTableLock);

                // RtlInsertElementGenericTable�� ���� ��Ҹ� ��ȯ
                PDLP_TABLE_ENTRY oldEntry = (PDLP_TABLE_ENTRY)RtlInsertElementGenericTable(
                    &g_DlpTable,
                    &entryToInsert,
                    sizeof(entryToInsert),
                    &newElement
                );
                if (oldEntry == nullptr) {
                    // AllocateRoutine ���� �� �ɰ��� ����.
                    ExReleasePushLockExclusive(&g_DlpTableLock);
                    // �߿�: ȣ���ڴ� NewInfo�� ������ å���� ����.
                    return FALSE;
                }

                // newElement�� FALSE��� ���� ���� ��Ұ� oldEntry�� ��ȯ�Ǿ����� �ǹ� -> ������ �̹� �� �ش� Ű�� �ʿ� �־�����, �� Entry�ּҸ� ��ȯ��.
                if (newElement == FALSE)
                {
                    // ���� ��Ұ� ����Ű�� Info�� ȭ��Ʈ����Ʈ�� �����ؾ� �մϴ�.
                    if (oldEntry->Info)
                    {
                        auto oldInfo = oldEntry->Info;
                        PLIST_ENTRY pos, next;

                        for (pos = oldInfo->Policy.WhiteListHeader.Flink;
                            pos != &oldInfo->Policy.WhiteListHeader;
                            pos = next)
                        {
                            next = pos->Flink;
                            auto whiteListNode = CONTAINING_RECORD(pos, DLP_WhiteList_Node_Policy, Entry);
                            RemoveEntryList(&whiteListNode->Entry);
                            ExFreePoolWithTag(whiteListNode, 'LDPD');
                        }
                        ExFreePoolWithTag(oldInfo, 'LDPD');
                    }

                    // oldEntry ��ü�� RtlInsertElementGenericTable�� ���� �̹� �����Ǿ����ϴ�.
                    // (��Ȯ����, �� entry �����Ͱ� oldEntry�� �ִ� �޸� ������ ����������ϴ�)
                }
                else
                {
                    // �� ��ҷ� Insert��.
                }

                ExReleasePushLockExclusive(&g_DlpTableLock);

                return TRUE;
            }

            PDLP_Info Lookup(ULONG64 FileRef) {
                DLP_TABLE_ENTRY key = { FileRef, nullptr };
                ExAcquirePushLockShared(&g_DlpTableLock);
                PDLP_TABLE_ENTRY found = (PDLP_TABLE_ENTRY)
                    RtlLookupElementGenericTable(&g_DlpTable, &key);
                ExReleasePushLockShared(&g_DlpTableLock);

                return found ? found->Info : nullptr;
            }

            BOOLEAN Remove(ULONG64 FileRef) {
                ExAcquirePushLockExclusive(&g_DlpTableLock);

                // 1. ������ ��Ҹ� ã���ϴ�.
                DLP_TABLE_ENTRY key = { FileRef, nullptr };
                PDLP_TABLE_ENTRY entry = (PDLP_TABLE_ENTRY)RtlLookupElementGenericTable(&g_DlpTable, &key);

                if (!entry) {
                    // ��Ұ� ������ �׳� ����
                    ExReleasePushLockExclusive(&g_DlpTableLock);
                    return FALSE;
                }

                // 2. Info �� ���� ȭ��Ʈ����Ʈ�� ���� �����մϴ�. (CleanUp_DLP ������ ����)
                if (entry->Info)
                {
                    auto info = entry->Info;
                    PLIST_ENTRY pos, next;

                    for (pos = info->Policy.WhiteListHeader.Flink;
                        pos != &info->Policy.WhiteListHeader;
                        pos = next)
                    {
                        next = pos->Flink;
                        auto whiteListNode = CONTAINING_RECORD(pos, DLP_WhiteList_Node_Policy, Entry);
                        RemoveEntryList(&whiteListNode->Entry);
                        ExFreePoolWithTag(whiteListNode, 'LDPD');
                    }

                    ExFreePoolWithTag(info, 'LDPD');
                }

                // 3. ���̺��� ��Ҹ� �����մϴ�. (�̶� entry ��ü�� FreeRoutine�� ���� ������)
                BOOLEAN result = RtlDeleteElementGenericTable(&g_DlpTable, entry);

                ExReleasePushLockExclusive(&g_DlpTableLock);
                return result;
            }
		}
	}

    NTSTATUS DLP_INITIALIZE()
    {
        // �ؽø� �ʱ�ȭ
        return resource::hashMap::Initialize_DLP_HashMap();
    }

    namespace Helper
    {
        // Step 1: DLP Info ����
        BOOLEAN Make_DLP_INFO(
            DLP::resource::PDLP_Info* Out_DLP_Info,
            ULONG64 ProtectFile_FRN,
            ULONG64 FileSize,
            struct DLP::resource::_DLP_Policy GLOBAL_policy
        )
        {
            if (!Out_DLP_Info )
                return FALSE;

            auto info = (DLP::resource::PDLP_Info)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DLP::resource::DLP_Info), 'LDPD');
            if (!info)
                return FALSE;

            RtlZeroMemory(info, sizeof(DLP::resource::DLP_Info));

            info->FILE.FileReferenceNumber = ProtectFile_FRN;
            info->FILE.FileSize = FileSize;

            info->Policy.Global.Policy = GLOBAL_policy;

            // WhiteList LIST Header �ʱ�ȭ
            InitializeListHead(&info->Policy.WhiteListHeader);

            *Out_DLP_Info = info;
            return TRUE;
        }

        BOOLEAN Set_Enable_DLP_INFO(ULONG64 ProcessEXE_FRN)
        {
            auto info = DLP::resource::hashMap::Lookup(ProcessEXE_FRN);
            if (!info)
                return FALSE;

            info->is_enable = TRUE;
            return TRUE;
        }

        // Step 1b: �̹� �����ϸ� ������Ʈ, ������ �߰�
        BOOLEAN Update_DLP_INFO_Global(
            ULONG64 ProcessEXE_FRN,
            struct DLP::resource::_DLP_Policy GLOBAL_policy
        )
        {
            auto info = DLP::resource::hashMap::Lookup(ProcessEXE_FRN);
            if (!info)
                return FALSE;

            info->Policy.Global.Policy = GLOBAL_policy;
            return TRUE;
        }

        BOOLEAN Remove_DLP_INFO(
            ULONG64 ProcessEXE_FRN
        )
        {
            return DLP::resource::hashMap::Remove(ProcessEXE_FRN);
        }

        // Step 2: ȭ��Ʈ����Ʈ ������Ʈ
        BOOLEAN Update_WhiteList(
            DLP::resource::PDLP_Info In_DLP_Info,
            ULONG64 ProcessEXE_FRN,
            struct DLP::resource::_DLP_Policy WHITE_policy
        )
        {
            if (!In_DLP_Info)
                return FALSE;

            // �̹� �����ϴ� ��� �˻�
            PLIST_ENTRY pos;
            for (pos = In_DLP_Info->Policy.WhiteListHeader.Flink;
                pos != &In_DLP_Info->Policy.WhiteListHeader;
                pos = pos->Flink)
            {
                auto node = CONTAINING_RECORD(pos, DLP::resource::DLP_WhiteList_Node_Policy, Entry);
                if (node->ProcessEXE_FileReferenceNumber == ProcessEXE_FRN)
                {
                    node->Policy = WHITE_policy; // ������Ʈ
                    return TRUE;
                }
            }

            // �������� ������ �� ��� ����
            auto newNode = (DLP::resource::P_DLP_WhiteList_Node_Policy)
                ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DLP::resource::DLP_WhiteList_Node_Policy), 'LDPD');
            if (!newNode)
                return FALSE;

            RtlZeroMemory(newNode, sizeof(DLP::resource::DLP_WhiteList_Node_Policy));

            newNode->Policy = WHITE_policy;
            newNode->ProcessEXE_FileReferenceNumber = ProcessEXE_FRN;

            InsertTailList(&In_DLP_Info->Policy.WhiteListHeader, &newNode->Entry);

            return TRUE;
        }

        BOOLEAN Remove_WhiteList(
            ULONG64 ProcessEXE_FRN,
            DLP::resource::PDLP_Info In_DLP_Info
        )
        {
            if (!In_DLP_Info)
                return FALSE;

            PLIST_ENTRY pos, next;
            for (pos = In_DLP_Info->Policy.WhiteListHeader.Flink;
                pos != &In_DLP_Info->Policy.WhiteListHeader;
                pos = next)
            {
                next = pos->Flink;

                auto node = CONTAINING_RECORD(pos, DLP::resource::DLP_WhiteList_Node_Policy, Entry);
                if (node->ProcessEXE_FileReferenceNumber == ProcessEXE_FRN)
                {
                    RemoveEntryList(&node->Entry);
                    ExFreePoolWithTag(node, 'LDPD');
                    return TRUE;
                }
            }

            return FALSE; // �ش� ��� ����
        }

        // ȭ��Ʈ ����Ʈ ��ȸ
         BOOLEAN Lookup_WhiteList(
            DLP::resource::PDLP_Info In_DLP_Info,
            ULONG64 ProcessEXE_FRN,

            DLP::resource::P_DLP_WhiteList_Node_Policy out_WhiteListNode
        )
        {
            if (!In_DLP_Info || !out_WhiteListNode)
                return FALSE;

            PLIST_ENTRY pos;
            for (pos = In_DLP_Info->Policy.WhiteListHeader.Flink;
                pos != &In_DLP_Info->Policy.WhiteListHeader;
                pos = pos->Flink)
            {
                auto node = CONTAINING_RECORD(pos, DLP::resource::DLP_WhiteList_Node_Policy, Entry);
                if (node->ProcessEXE_FileReferenceNumber == ProcessEXE_FRN)
                {
                    *out_WhiteListNode = *node;
                    return TRUE;
                }
            }

            return FALSE;
        }
    }

    BOOLEAN CleanUp_DLP()
    {
        // ���̺� ��ü�� �����ϹǷ� Exclusive Lock�� ȹ���մϴ�.
        ExAcquirePushLockExclusive(&resource::hashMap::g_DlpTableLock);

        // ���̺��� ������� ���� ���� �ݺ��մϴ�.
        while (!RtlIsGenericTableEmpty(&resource::hashMap::g_DlpTable))
        {
            // ���̺��� ù ��° ��Ҹ� �����ɴϴ�.
            auto entry = static_cast<resource::hashMap::PDLP_TABLE_ENTRY>(
                RtlEnumerateGenericTable(&resource::hashMap::g_DlpTable, TRUE)
                );

            if (entry == nullptr)
            {
                // ���̺��� ������� �ʴٰ� �ߴµ� ��Ұ� ������ ������ Ż���մϴ�. (���� �ڵ�)
                break;
            }

            // 1. ��å�� �ִ� ȭ��Ʈ ����Ʈ�� ��� ��ȸ�ϸ� �����մϴ�.
            if (entry->Info)
            {
                auto info = entry->Info;
                PLIST_ENTRY pos, next;

                // ����Ʈ�� ��ȸ�ϸ鼭 ��带 ������ ���� ���� ��带 �̸� �����صδ� ���� �����մϴ�.
                for (pos = info->Policy.WhiteListHeader.Flink;
                    pos != &info->Policy.WhiteListHeader;
                    pos = next)
                {
                    next = pos->Flink; // ���� ��带 �����ϱ� ���� ���� ��带 ����Ŵ

                    auto whiteListNode = CONTAINING_RECORD(pos, resource::DLP_WhiteList_Node_Policy, Entry);

                    RemoveEntryList(&whiteListNode->Entry); // ����Ʈ���� ������ ����
                    ExFreePoolWithTag(whiteListNode, 'LDPD'); // ��� �޸� ����
                }

                // ȭ��Ʈ����Ʈ ���� ��, DLP_Info ����ü ��ü�� �����մϴ�.
                ExFreePoolWithTag(info, 'LDPD');
                entry->Info = nullptr; // Dangling ������ ����
            }

            // 2. �ؽøʿ��� ���� ��Ҹ� �����մϴ�.
            // �� �Լ��� ���������� FreeRoutine�� ȣ���Ͽ� 'entry' ��ü�� �޸𸮵� �����մϴ�.
            RtlDeleteElementGenericTable(&resource::hashMap::g_DlpTable, entry);
        }

        // ���� �����մϴ�.
        ExReleasePushLockExclusive(&resource::hashMap::g_DlpTableLock);

        return TRUE;
    }

}