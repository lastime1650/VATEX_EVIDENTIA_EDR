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

            NTSTATUS GetObjectNameInfo(PVOID pObject, POBJECT_NAME_INFORMATION* ppNameInfo)
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
            VOID FreeObjectNameInfo(POBJECT_NAME_INFORMATION pNameInfo)
            {
                if (pNameInfo) {
                    ExFreePoolWithTag(pNameInfo, 'mNsO');
                }
            }

            BOOLEAN SendRegistryEvent(
                PCHAR KeyClass,
                HANDLE ProcessId,
                ULONG64 NanoTimestamp,
                PVOID Object,
                PUNICODE_STRING Name,
                PUNICODE_STRING CompleteName,
                PUNICODE_STRING OldName,
                PUNICODE_STRING NewName
            )
            {
                if (CompleteName) {

                    if (!CompleteName->Buffer)
                        return FALSE;

                    // 바로 문자열 사용 가능
                    return EDR::LogSender::function::Registry_by_CompleteorObjectNameLog(
                        KeyClass, ProcessId, NanoTimestamp, CompleteName);
                }
                
                else if (Object && !Name) {
                    // Object 기반 (Key Path)
                    POBJECT_NAME_INFORMATION nameinfo = NULL;
                    if (!NT_SUCCESS(GetObjectNameInfo(Object, &nameinfo)) || !nameinfo || !nameinfo->Name.Buffer)
                        return FALSE;

                    BOOLEAN status = EDR::LogSender::function::Registry_by_CompleteorObjectNameLog(
                        KeyClass, ProcessId, NanoTimestamp, &nameinfo->Name);

                    FreeObjectNameInfo(nameinfo);
                    return status;
                }
                else if (Object && Name) {
                    // Object + Name 기반 (Key Path + ValueName)
                    POBJECT_NAME_INFORMATION nameinfo = NULL;
                    if (!NT_SUCCESS(GetObjectNameInfo(Object, &nameinfo)) || !nameinfo || !nameinfo->Name.Buffer)
                        return FALSE;

                    // Key 경로와 ValueName을 합쳐서 로그 전송 (예: "HKLM\...\SomeKey\ValueName")
                    UNICODE_STRING fullPath;
                    RtlInitEmptyUnicodeString(&fullPath, NULL, 0);
                    // 이 부분은 실제 구현에서 동적 버퍼 할당 필요

                    BOOLEAN status = EDR::LogSender::function::Registry_by_CompleteorObjectNameLog(
                        KeyClass, ProcessId, NanoTimestamp, &nameinfo->Name );

                    FreeObjectNameInfo(nameinfo);
                    return status;
                }
                else if (Object && OldName && NewName)
                {
                    if (!OldName->Buffer || !OldName->Length || !NewName->Buffer || !NewName->Length)
                        return FALSE;

                    POBJECT_NAME_INFORMATION nameinfo = NULL;
                    if (!NT_SUCCESS(GetObjectNameInfo(Object, &nameinfo)) || !nameinfo || !nameinfo->Name.Buffer)
                        return FALSE;

					BOOLEAN status = EDR::LogSender::function::Registry_by_OldNewNameLog(
						KeyClass, ProcessId, NanoTimestamp, &nameinfo->Name, OldName, NewName);

                    FreeObjectNameInfo(nameinfo);
                    return status;
                }

                return FALSE;
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
                if (!Argument2 || !Argument1 || !EDR::Util::Shared::USER_AGENT::ProcessId)
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


                CHAR RegClassStr[256];
                RtlZeroMemory(RegClassStr, sizeof(RegClassStr) );

                switch (NotifyClass)
                {
                    case RegNtPreCreateKeyEx:
                    {
                        PREG_CREATE_KEY_INFORMATION pInfo = (PREG_CREATE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "PreCreateKeyEx",
                            ProcessId, Nano_Timestamp,
                            nullptr, nullptr, pInfo->CompleteName, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreQueryKey:
                    {
                        PREG_QUERY_KEY_INFORMATION pInfo = (PREG_QUERY_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "PreQueryKey",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreQueryValueKey:
                    {
                        PREG_QUERY_VALUE_KEY_INFORMATION pInfo = (PREG_QUERY_VALUE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "PreQueryValueKey",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, pInfo->ValueName, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreQueryMultipleValueKey:
                    {
                        PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION pInfo = (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "PreQueryMultipleValueKey",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreKeyHandleClose:
                    {
                        PREG_KEY_HANDLE_CLOSE_INFORMATION pInfo = (PREG_KEY_HANDLE_CLOSE_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "PreKeyHandleClose",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreFlushKey:
                    {
                        PREG_FLUSH_KEY_INFORMATION pInfo = (PREG_FLUSH_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "RegNtPreFlushKey",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreLoadKey:
                    {
                        PREG_LOAD_KEY_INFORMATION pInfo = (PREG_LOAD_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "RegNtPreLoadKey",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreUnLoadKey:
                    {
                        PREG_UNLOAD_KEY_INFORMATION pInfo = (PREG_UNLOAD_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "RegNtPreUnLoadKey",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreQueryKeySecurity:
                    {
                        PREG_QUERY_KEY_SECURITY_INFORMATION pInfo = (PREG_QUERY_KEY_SECURITY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "RegNtPreQueryKeySecurity",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreSetKeySecurity:
                    {
                        PREG_SET_KEY_SECURITY_INFORMATION pInfo = (PREG_SET_KEY_SECURITY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "RegNtPreSetKeySecurity",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreRestoreKey:
                    {
                        PREG_RESTORE_KEY_INFORMATION pInfo = (PREG_RESTORE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "RegNtPreRestoreKey",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreSaveKey:
                    {
                        PREG_SAVE_KEY_INFORMATION pInfo = (PREG_SAVE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "RegNtPreSaveKey",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreReplaceKey:
                    {
                        PREG_REPLACE_KEY_INFORMATION pInfo = (PREG_REPLACE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "PreReplaceKey",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, pInfo->OldFileName, pInfo->NewFileName);
                        break;
                    }
                    case RegNtPreQueryKeyName:
                    {
                        PREG_QUERY_KEY_NAME pInfo = (PREG_QUERY_KEY_NAME)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "PreQueryKeyName",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPreSaveMergedKey:
                    {
                        PREG_SAVE_MERGED_KEY_INFORMATION pInfo = (PREG_SAVE_MERGED_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        helper::SendRegistryEvent(
                            "PreSaveMergedKey",
                            ProcessId, Nano_Timestamp,
                            pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostCreateKeyEx:
                    {
                        PREG_POST_CREATE_KEY_INFORMATION pInfo = (PREG_POST_CREATE_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->CompleteName)
                            helper::SendRegistryEvent(
                                "PostCreateKeyEx",
                                ProcessId, Nano_Timestamp,
                                nullptr, pInfo->CompleteName, nullptr, nullptr, nullptr);
                        break;
                    }
                    /*
                    case RegNtPostOpenKeyEx:
                    {
                        PREG_POST_OPEN_KEY_INFORMATION pInfo = (PREG_POST_OPEN_KEY_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->CompleteName)
                            helper::SendRegistryEvent(
                                "RegNtPostOpenKeyEx",
                                ProcessId, Nano_Timestamp,
                                nullptr, nullptr, pInfo->CompleteName, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostDeleteKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostDeleteKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        
                        break;
                    }
                    case RegNtPostSetValueKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostSetValueKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostDeleteValueKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostDeleteValueKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostSetInformationKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostSetInformationKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostRenameKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostRenameKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostQueryKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostQueryKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostQueryValueKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostQueryValueKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostQueryMultipleValueKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostQueryMultipleValueKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostKeyHandleClose:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostKeyHandleClose",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostFlushKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostFlushKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostLoadKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostLoadKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostUnLoadKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostUnLoadKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostQueryKeySecurity:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostQueryKeySecurity",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostSetKeySecurity:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostSetKeySecurity",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostRestoreKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostRestoreKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostSaveKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostSaveKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostReplaceKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostReplaceKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostQueryKeyName:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostQueryKeyName",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }
                    case RegNtPostSaveMergedKey:
                    {
                        PREG_POST_OPERATION_INFORMATION pInfo = (PREG_POST_OPERATION_INFORMATION)KEY_INFORMATION_STRUCT_ADDRESS;
                        if (NT_SUCCESS(pInfo->Status) && pInfo->Object)
                            helper::SendRegistryEvent(
                                "RegNtPostSaveMergedKey",
                                ProcessId, Nano_Timestamp,
                                pInfo->Object, nullptr, nullptr, nullptr, nullptr);
                        break;
                    }*/
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