#include "Registry.hpp"
#include "API.hpp"
#include "LogSender.hpp"

namespace EDR
{
	namespace Registry
	{
		namespace resource
		{
			BOOLEAN is_complete_init = FALSE;
			LARGE_INTEGER Cookie_for_unload = { 0, };
		}

		namespace helper
		{

            static NTSTATUS GetObjectNameInfo(PVOID pObject, POBJECT_NAME_INFORMATION* ppNameInfo)
            {
                NTSTATUS status;
                ULONG returnedLength = 0;
                POBJECT_NAME_INFORMATION nameInfo = nullptr;

                if (!pObject || !ppNameInfo) {
                    return STATUS_INVALID_PARAMETER;
                }
                *ppNameInfo = nullptr;

                status = ObQueryNameString(pObject, nullptr, 0, &returnedLength);
                if (status != STATUS_INFO_LENGTH_MISMATCH) {
                    return status;
                }

                nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, returnedLength, 'mNsO');
                if (!nameInfo) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                status = ObQueryNameString(pObject, nameInfo, returnedLength, &returnedLength);
                if (!NT_SUCCESS(status)) {
                    ExFreePoolWithTag(nameInfo, 'mNsO');
                    return status;
                }

                *ppNameInfo = nameInfo;
                return STATUS_SUCCESS;
            }

            // GetObjectNameInfo로 할당된 메모리를 해제합니다.
            static VOID FreeObjectNameInfo(POBJECT_NAME_INFORMATION pNameInfo)
            {
                if (pNameInfo) {
                    ExFreePoolWithTag(pNameInfo, 'mNsO');
                }
            }

            BOOLEAN SendLoad_by_CompleteName(EDR::EventLog::Enum::Registry::Registry_enum KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp, PUNICODE_STRING CompleteName)
            {
                return EDR::LogSender::function::Registry_by_CompleteorObjectNameLog(KeyClass, ProcessId, NanoTimestamp, CompleteName);
            }
            BOOLEAN SendLoad_by_Object(EDR::EventLog::Enum::Registry::Registry_enum KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp, PVOID Object)
            {
                POBJECT_NAME_INFORMATION nameinfo = NULL;
                if (!NT_SUCCESS(GetObjectNameInfo(Object, &nameinfo)) || !nameinfo || !nameinfo->Name.Buffer)
                    return FALSE;

                BOOLEAN status = EDR::LogSender::function::Registry_by_CompleteorObjectNameLog(KeyClass, ProcessId, NanoTimestamp, &nameinfo->Name);

                FreeObjectNameInfo(nameinfo);

                return status;
            }
            BOOLEAN SendLoad_by_SetName(EDR::EventLog::Enum::Registry::Registry_enum KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp, PVOID Object, PUNICODE_STRING Name)
            {

                return TRUE;
            }
            BOOLEAN SendEvent_PreSetInformationKey(HANDLE ProcessId, ULONG64 NanoTimestamp, PREG_SET_INFORMATION_KEY_INFORMATION pInfo)
            {
                return TRUE;
            }
            BOOLEAN SendEvent_PreLoadKey(HANDLE ProcessId, ULONG64 NanoTimestamp, PREG_LOAD_KEY_INFORMATION pInfo)
            {
                return TRUE;
            }

		}

		namespace Handler
		{
			extern "C" NTSTATUS RegisterCallbacksHandler(
				_In_ PVOID CallbackContext,
				_In_opt_ PVOID Argument1,
				_In_opt_ PVOID Argument2
			)
			{
                if (!Argument2 || !Argument1)
                    return STATUS_SUCCESS;

                HANDLE ProcessId = PsGetCurrentProcessId();
                ULONG64 Nano_Timestamp = EDR::Util::Timestamp::Get_LocalTimestamp_Nano();
				// >= APC_LEVEL
				NTSTATUS status = STATUS_SUCCESS;

				if(PsIsSystemProcess(PsGetCurrentProcess()))
					return status;

				/*
					// CallbackContext: 0000000000000000 / Argument1: 0000000000000019 / Argument2: FFFFF08427FCD850
				*/
				// Key 클래스 ( 레지스트리 함수 추출 )
                REG_NOTIFY_CLASS NotifyClass;
                RtlCopyMemory(&NotifyClass, &Argument1, sizeof(REG_NOTIFY_CLASS));
				// Key Information 시작주소
				PVOID KEY_INFORMATION_STRUCT_ADDRESS = Argument2;
				
                switch (NotifyClass)
                {
                    //
                    // PRE-OPERATIONS
                    //
                case RegNtPreCreateKeyEx:
                {
                    
                    PREG_CREATE_KEY_INFORMATION pInfo = (PREG_CREATE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    if(pInfo->CompleteName)
                        helper::SendLoad_by_CompleteName(EDR::EventLog::Enum::Registry::RegNtPreCreateKeyEx, ProcessId, Nano_Timestamp, pInfo->CompleteName);
                    break;
                }
                case RegNtPreOpenKeyEx:
                {
                    PREG_OPEN_KEY_INFORMATION pInfo = (PREG_OPEN_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    if (pInfo->CompleteName)
                        helper::SendLoad_by_CompleteName(EDR::EventLog::Enum::Registry::RegNtPreCreateKeyEx, ProcessId, Nano_Timestamp, pInfo->CompleteName);
                    break;
                }
                case RegNtPreDeleteKey:
                {
                    PREG_DELETE_KEY_INFORMATION pInfo = (PREG_DELETE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendLoad_by_Object(EDR::EventLog::Enum::Registry::RegNtPreCreateKeyEx, ProcessId, Nano_Timestamp, pInfo->Object);
                    break;
                }
                case RegNtPreSetValueKey:
                {
                    PREG_SET_VALUE_KEY_INFORMATION pInfo = (PREG_SET_VALUE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendLoad_by_SetName(EDR::EventLog::Enum::Registry::RegNtPreSetValueKey, ProcessId, Nano_Timestamp, pInfo->Object, pInfo->ValueName);
                    break;
                }
                case RegNtPreDeleteValueKey:
                {
                    PREG_DELETE_VALUE_KEY_INFORMATION pInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendLoad_by_SetName(EDR::EventLog::Enum::Registry::RegNtPreDeleteValueKey, ProcessId, Nano_Timestamp, pInfo->Object, pInfo->ValueName);
                    break;
                }
                case RegNtPreSetInformationKey:
                {
                    PREG_SET_INFORMATION_KEY_INFORMATION pInfo = (PREG_SET_INFORMATION_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreSetInformationKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreRenameKey:
                {
                    PREG_RENAME_KEY_INFORMATION pInfo = (PREG_RENAME_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendLoad_by_SetName(EDR::EventLog::Enum::Registry::RegNtPreRenameKey, ProcessId, Nano_Timestamp, pInfo->Object, pInfo->NewName);
                    break;
                }
                /*
                case RegNtPreQueryKey:
                {
                    PREG_QUERY_KEY_INFORMATION pInfo = (PREG_QUERY_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreQueryKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreQueryValueKey:
                {
                    PREG_QUERY_VALUE_KEY_INFORMATION pInfo = (PREG_QUERY_VALUE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreQueryValueKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreQueryMultipleValueKey:
                {
                    PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION pInfo = (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreQueryMultipleValueKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreKeyHandleClose:
                {
                    PREG_KEY_HANDLE_CLOSE_INFORMATION pInfo = (PREG_KEY_HANDLE_CLOSE_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreKeyHandleClose(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreFlushKey:
                {
                    PREG_FLUSH_KEY_INFORMATION pInfo = (PREG_FLUSH_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreFlushKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreLoadKey:
                {
                    PREG_LOAD_KEY_INFORMATION pInfo = (PREG_LOAD_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreLoadKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreUnLoadKey:
                {
                    PREG_UNLOAD_KEY_INFORMATION pInfo = (PREG_UNLOAD_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreUnLoadKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreQueryKeySecurity:
                {
                    PREG_QUERY_KEY_SECURITY_INFORMATION pInfo = (PREG_QUERY_KEY_SECURITY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreQueryKeySecurity(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreSetKeySecurity:
                {
                    PREG_SET_KEY_SECURITY_INFORMATION pInfo = (PREG_SET_KEY_SECURITY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreSetKeySecurity(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreRestoreKey:
                {
                    PREG_RESTORE_KEY_INFORMATION pInfo = (PREG_RESTORE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreRestoreKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreSaveKey:
                {
                    PREG_SAVE_KEY_INFORMATION pInfo = (PREG_SAVE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreSaveKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreReplaceKey:
                {
                    PREG_REPLACE_KEY_INFORMATION pInfo = (PREG_REPLACE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreReplaceKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreQueryKeyName:
                {
                    PREG_QUERY_KEY_NAME pInfo = (PREG_QUERY_KEY_NAME)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreQueryKeyName(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPreSaveMergedKey:
                {
                    PREG_SAVE_MERGED_KEY_INFORMATION pInfo = (PREG_SAVE_MERGED_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PreSaveMergedKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }

                //
                // POST-OPERATIONS
                //
                case RegNtPostCreateKeyEx:
                {
                    PREG_POST_CREATE_KEY_INFORMATION pInfo = (PREG_POST_CREATE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostCreateKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostOpenKeyEx:
                {
                    PREG_POST_OPEN_KEY_INFORMATION pInfo = (PREG_POST_OPEN_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostOpenKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostDeleteKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostDeleteKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostSetValueKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostSetValueKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostDeleteValueKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostDeleteValueKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostSetInformationKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostSetInformationKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostRenameKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostRenameKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostQueryKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostQueryKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostQueryValueKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostQueryValueKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostQueryMultipleValueKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostQueryMultipleValueKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostKeyHandleClose:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostKeyHandleClose(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostFlushKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostFlushKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostLoadKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostLoadKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostUnLoadKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostUnLoadKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostQueryKeySecurity:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostQueryKeySecurity(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostSetKeySecurity:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostSetKeySecurity(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostRestoreKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostRestoreKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostSaveKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostSaveKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostReplaceKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostReplaceKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostQueryKeyName:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostQueryKeyName(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                case RegNtPostSaveMergedKey:
                {
                    PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                    helper::SendEvent_PostSaveMergedKey(ProcessId, Nano_Timestamp, pInfo);
                    break;
                }
                */
                default:
                    // 처리하지 않는 알림 클래스
                    break;
                }
				return status;
			}
		}

		NTSTATUS Load_RegistryCallback(PDRIVER_OBJECT driverobject)
		{
			UNICODE_STRING Altitude;
			RtlInitUnicodeString(
				&Altitude,
				RegistryAltitude
			);

			

			NTSTATUS status = CmRegisterCallbackEx(
				Handler::RegisterCallbacksHandler,
				&Altitude,
				driverobject,
				NULL,
				&resource::Cookie_for_unload,
				NULL
			);

            return status;
		}
		VOID CleanUp_RegistryCallback()
		{
			if(resource::is_complete_init)
				CmUnRegisterCallback(
					resource::Cookie_for_unload
				);
		}

	}
}