#include "DLP.hpp"

namespace DLP
{
	namespace resource
	{
		namespace hashMap
		{
            RTL_GENERIC_TABLE g_DlpTable;
            EX_PUSH_LOCK g_DlpTableLock;

            // FileReferenceNumber 값은 절대적으로 고유값이며 그래야한다. (한 볼륨내 )
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

                // RtlInsertElementGenericTable은 기존 요소를 반환
                PDLP_TABLE_ENTRY oldEntry = (PDLP_TABLE_ENTRY)RtlInsertElementGenericTable(
                    &g_DlpTable,
                    &entryToInsert,
                    sizeof(entryToInsert),
                    &newElement
                );
                if (oldEntry == nullptr) {
                    // AllocateRoutine 실패 등 심각한 오류.
                    ExReleasePushLockExclusive(&g_DlpTableLock);
                    // 중요: 호출자는 NewInfo를 해제할 책임이 있음.
                    return FALSE;
                }

                // newElement가 FALSE라는 것은 기존 요소가 oldEntry로 반환되었음을 의미 -> 이전에 이미 이 해당 키가 맵에 있었으며, 그 Entry주소를 반환함.
                if (newElement == FALSE)
                {
                    // 기존 요소가 가리키던 Info와 화이트리스트를 해제해야 합니다.
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

                    // oldEntry 자체는 RtlInsertElementGenericTable에 의해 이미 해제되었습니다.
                    // (정확히는, 새 entry 데이터가 oldEntry가 있던 메모리 공간에 덮어써졌습니다)
                }
                else
                {
                    // 새 요소로 Insert됨.
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

                // 1. 삭제할 요소를 찾습니다.
                DLP_TABLE_ENTRY key = { FileRef, nullptr };
                PDLP_TABLE_ENTRY entry = (PDLP_TABLE_ENTRY)RtlLookupElementGenericTable(&g_DlpTable, &key);

                if (!entry) {
                    // 요소가 없으면 그냥 종료
                    ExReleasePushLockExclusive(&g_DlpTableLock);
                    return FALSE;
                }

                // 2. Info 및 내부 화이트리스트를 먼저 해제합니다. (CleanUp_DLP 로직과 동일)
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

                // 3. 테이블에서 요소를 제거합니다. (이때 entry 자체도 FreeRoutine에 의해 해제됨)
                BOOLEAN result = RtlDeleteElementGenericTable(&g_DlpTable, entry);

                ExReleasePushLockExclusive(&g_DlpTableLock);
                return result;
            }
		}
	}

    NTSTATUS DLP_INITIALIZE()
    {
        // 해시맵 초기화
        return resource::hashMap::Initialize_DLP_HashMap();
    }

    namespace Helper
    {
        // Step 1: DLP Info 생성
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

            // WhiteList LIST Header 초기화
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

        // Step 1b: 이미 존재하면 업데이트, 없으면 추가
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

        // Step 2: 화이트리스트 업데이트
        BOOLEAN Update_WhiteList(
            DLP::resource::PDLP_Info In_DLP_Info,
            ULONG64 ProcessEXE_FRN,
            struct DLP::resource::_DLP_Policy WHITE_policy
        )
        {
            if (!In_DLP_Info)
                return FALSE;

            // 이미 존재하는 노드 검색
            PLIST_ENTRY pos;
            for (pos = In_DLP_Info->Policy.WhiteListHeader.Flink;
                pos != &In_DLP_Info->Policy.WhiteListHeader;
                pos = pos->Flink)
            {
                auto node = CONTAINING_RECORD(pos, DLP::resource::DLP_WhiteList_Node_Policy, Entry);
                if (node->ProcessEXE_FileReferenceNumber == ProcessEXE_FRN)
                {
                    node->Policy = WHITE_policy; // 업데이트
                    return TRUE;
                }
            }

            // 존재하지 않으면 새 노드 생성
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

            return FALSE; // 해당 노드 없음
        }

        // 화이트 리스트 조회
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
        // 테이블 전체를 수정하므로 Exclusive Lock을 획득합니다.
        ExAcquirePushLockExclusive(&resource::hashMap::g_DlpTableLock);

        // 테이블이 비어있지 않은 동안 반복합니다.
        while (!RtlIsGenericTableEmpty(&resource::hashMap::g_DlpTable))
        {
            // 테이블의 첫 번째 요소를 가져옵니다.
            auto entry = static_cast<resource::hashMap::PDLP_TABLE_ENTRY>(
                RtlEnumerateGenericTable(&resource::hashMap::g_DlpTable, TRUE)
                );

            if (entry == nullptr)
            {
                // 테이블이 비어있지 않다고 했는데 요소가 없으면 루프를 탈출합니다. (안전 코드)
                break;
            }

            // 1. 정책에 있는 화이트 리스트를 모두 순회하며 해제합니다.
            if (entry->Info)
            {
                auto info = entry->Info;
                PLIST_ENTRY pos, next;

                // 리스트를 순회하면서 노드를 제거할 때는 다음 노드를 미리 저장해두는 것이 안전합니다.
                for (pos = info->Policy.WhiteListHeader.Flink;
                    pos != &info->Policy.WhiteListHeader;
                    pos = next)
                {
                    next = pos->Flink; // 현재 노드를 해제하기 전에 다음 노드를 가리킴

                    auto whiteListNode = CONTAINING_RECORD(pos, resource::DLP_WhiteList_Node_Policy, Entry);

                    RemoveEntryList(&whiteListNode->Entry); // 리스트에서 연결을 끊음
                    ExFreePoolWithTag(whiteListNode, 'LDPD'); // 노드 메모리 해제
                }

                // 화이트리스트 정리 후, DLP_Info 구조체 자체를 해제합니다.
                ExFreePoolWithTag(info, 'LDPD');
                entry->Info = nullptr; // Dangling 포인터 방지
            }

            // 2. 해시맵에서 현재 요소를 제거합니다.
            // 이 함수는 내부적으로 FreeRoutine을 호출하여 'entry' 자체의 메모리도 해제합니다.
            RtlDeleteElementGenericTable(&resource::hashMap::g_DlpTable, entry);
        }

        // 락을 해제합니다.
        ExReleasePushLockExclusive(&resource::hashMap::g_DlpTableLock);

        return TRUE;
    }

}