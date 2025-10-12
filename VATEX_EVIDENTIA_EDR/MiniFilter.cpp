#include "Minifilter.hpp"
#include "API.hpp"
#include "IOCTL.hpp"
#include "EventLog.hpp"
#include "LogSender.hpp"


extern "C" VOID InstanceTeardownCallback(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason);
extern "C" NTSTATUS InstanceSetupCallback(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);


namespace EDR
{
	namespace MiniFilter
	{
        namespace resource
        {
            PFLT_FILTER gFilterHandle = NULL;
        }
        

        const FLT_OPERATION_REGISTRATION Callback_s[] = {
            { IRP_MJ_CREATE, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_CREATE_NAMED_PIPE, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_CLOSE, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_READ, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_WRITE, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_QUERY_INFORMATION, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_SET_INFORMATION, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_QUERY_EA, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler,(PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_SET_EA, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_FLUSH_BUFFERS, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_QUERY_VOLUME_INFORMATION, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_SET_VOLUME_INFORMATION, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_DIRECTORY_CONTROL, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_FILE_SYSTEM_CONTROL, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_DEVICE_CONTROL, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_INTERNAL_DEVICE_CONTROL, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            //{ IRP_MJ_SHUTDOWN, 0, NULL, NULL }, // No post-operation callback
            { IRP_MJ_LOCK_CONTROL, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_CLEANUP, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_CREATE_MAILSLOT, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_QUERY_SECURITY, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_SET_SECURITY, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_POWER, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_SYSTEM_CONTROL, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_DEVICE_CHANGE, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_QUERY_QUOTA, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_SET_QUOTA, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_PNP, 0, (PFLT_PRE_OPERATION_CALLBACK)Handler::PRE::PRE_filter_Handler, (PFLT_POST_OPERATION_CALLBACK)Handler::POST::POST_filter_Handler },
            { IRP_MJ_OPERATION_END } // Array termination
        };

        NTSTATUS Load_MiniFilter(PDRIVER_OBJECT DriverObject)
        {
            NTSTATUS status;

            const FLT_REGISTRATION FilterRegistration = {
                sizeof(FLT_REGISTRATION),       // Size
                FLT_REGISTRATION_VERSION,       // Version
                0,                              // Flags
                NULL,                           // Context
                Callback_s,                      // Operation callbacks // 실제 핸들러와 IRP가 배열로 매핑된 정보
                NULL,                           // MiniFilterUnload
                InstanceSetupCallback,          // InstanceSetup
                NULL,                           // InstanceQueryTeardown
                InstanceTeardownCallback,       // InstanceTeardownStart
                InstanceTeardownCallback,       // InstanceTeardownComplete
                NULL,                           // GenerateFileName
                NULL,                           // GenerateDestinationFileName
                NULL                            // NormalizeNameComponent
            };

            status = FltRegisterFilter(DriverObject, &FilterRegistration, &resource::gFilterHandle);  // 등록
            if (NT_SUCCESS(status)) {

                status = FltStartFiltering(resource::gFilterHandle); // 시작
                if (!NT_SUCCESS(status)) {
                    CleanUp_MiniFilter();
                    return status;
                }

            }

            return status;
        }
        VOID CleanUp_MiniFilter()
        {
            if (resource::gFilterHandle != NULL) {
                FltUnregisterFilter(resource::gFilterHandle);
                resource::gFilterHandle = NULL; // 핸들을 NULL로 설정하여 더 이상 사용되지 않음을 표시
            }
        }
        
        namespace POST
        {
            
            namespace FltWorkItem
            {
                extern "C" VOID FltWorkItemThread(
                    _In_ PFLT_GENERIC_WORKITEM FltWorkItem,
                    _In_ PVOID FltObject,
                    _In_opt_ PVOID Context
                )
                {

                    //debug_break();

                    EDR::MiniFilter::resource::PHASH_WORK_ITEM_CONTEXT_DETAILS FltWorkItem_CTX = (EDR::MiniFilter::resource::PHASH_WORK_ITEM_CONTEXT_DETAILS)Context;

                    CHAR SHA256[SHA256_String_Byte_Length] = { 0 };
                    ULONG64 FileSize = 0;
                    // [핵심] 오래 걸리는 해싱 작업을 여기서 안전하게 수행
                    if (helper::Get_FileSHA256(
                        FltWorkItem_CTX->Instance,
                        FltWorkItem_CTX->FileObject,
                        SHA256,
                        &FileSize
                    ))
                    {
                        // 해싱 성공 시, 로그 전송 처리
                        // 파일 경로는 Pre-Op 컨텍스트에서 복사해서 pWorkContext에 담아와야 합니다.
                        // 이 예시에서는 생략합니다.

                        UNICODE_STRING NormalizedFilePath;
                        RtlInitUnicodeString(&NormalizedFilePath, FltWorkItem_CTX->NormalizedFilePath);


                        PCHAR Sha256 = NULL;
                        if (FileSize > 0)
                            Sha256 = SHA256;

                        EDR::LogSender::function::FilesystemLog(
                            FltWorkItem_CTX->ProcessId,
                            FltWorkItem_CTX->timestamp,
                            FltWorkItem_CTX->Action,
                            &NormalizedFilePath,
                            NULL,
                            Sha256
                        );
                        
                    }

                    if (FltWorkItem_CTX ->NormalizedFilePath)
                        ExFreePoolWithTag(FltWorkItem_CTX->NormalizedFilePath, PretoPost_CTX_ALLOC_TAG);


                    // [매우 중요] 사용 완료된 리소스 해제
                    FltObjectDereference(FltWorkItem_CTX->Instance);   // Post-Op에서 증가시킨 참조 카운트 감소
                    ObDereferenceObject(FltWorkItem_CTX->FileObject); // Post-Op에서 증가시킨 참조 카운트 감소


                    ExFreePoolWithTag(FltWorkItem_CTX, FLT_WORKITEM_CTX_ALLOC_TAG); // Details 해제
                    FltFreeGenericWorkItem(FltWorkItem); // 작업 아이템 자체를 해제
                }
            }
            extern "C" FLT_POSTOP_CALLBACK_STATUS
                POST_filter_Handler(
                    PFLT_CALLBACK_DATA Data,
                    PCFLT_RELATED_OBJECTS FltObjects,
                    EDR::MiniFilter::resource::PPretoPost_CTX CompletionContext,
                    FLT_POST_OPERATION_FLAGS Flags
                )
            {
                UNREFERENCED_PARAMETER(FltObjects);
                UNREFERENCED_PARAMETER(Data);
                //UNREFERENCED_PARAMETER(CompletionContext);
                UNREFERENCED_PARAMETER(Flags);

                BOOLEAN is_success_workitem = FALSE;
                switch (Data->Iopb->MajorFunction)
                {
                    case IRP_MJ_CREATE:
                    {
                        if (CompletionContext)
                        {
                            //debug_break();

                            EDR::EventLog::Enum::FileSystem::Filesystem_enum Action;
                            switch (Data->IoStatus.Information)
                            {
                            case FILE_CREATED:
                                // 파일이 새로 생성되었습니다.
                                Action = EDR::EventLog::Enum::FileSystem::create;
                                break;

                            case FILE_OPENED:
                                // 기존 파일이 열렸습니다.
                                Action = EDR::EventLog::Enum::FileSystem::open;
                                break;
                            
                            case FILE_OVERWRITTEN:
                                // 기존 파일 위에 덮어썼습니다. (예: CreateDisposition = FILE_OVERWRITE_IF)
                                Action = EDR::EventLog::Enum::FileSystem::overwritten;
                                break;

                            case FILE_SUPERSEDED:
                                // 기존 파일을 대체했습니다. (예: CreateDisposition = FILE_SUPERSEDE)
                                Action = EDR::EventLog::Enum::FileSystem::superseded;
                                break;

                            case FILE_EXISTS:
                                // 파일이 이미 존재하여 작업이 실패했습니다. (예: CreateDisposition = FILE_CREATE)
                                // 이 경우는 NT_SUCCESS가 아니므로 위의 if문에서 걸러질 수 있습니다.
                                // 상태 코드가 STATUS_OBJECT_NAME_COLLISION 일 때 이 값이 설정됩니다.
                                Action = EDR::EventLog::Enum::FileSystem::exists;
                                break;
                            default:
                            {
                                if (CompletionContext->NormalizedFilePath)
                                    ExFreePoolWithTag(CompletionContext->NormalizedFilePath, PretoPost_CTX_ALLOC_TAG);
                                ExFreePoolWithTag(CompletionContext, PretoPost_CTX_ALLOC_TAG);
                                return FLT_POSTOP_FINISHED_PROCESSING;
                            }
                            }


                            //
                            //debug_log("%ws \n", (PWCH)(CompletionContext->NormalizedFilePath));

                            /*
                                파일 해싱을 하려면? 
                                
                                이 POST-LEVEL에서도 해싱이 실패하는 경우 ( 비안전 레벨 )가 있었으므로, 지연된 Flt 전용 WorkItem을 사용하여
                                << 데드락 >> 없이 진행.ㅇㅇ
                            
                            ULONG64 FileSize = 0;
                            CHAR SHA256[SHA256_String_Byte_Length] = { 0 };
                            if (helper::Get_FileSHA256(
                                FltObjects->Instance,
                                FltObjects->FileObject,
                                SHA256,
                                &FileSize
                            ))
                            {
                                // 해싱 성공 시,
                                UNICODE_STRING NormalizedFilePath;
                                RtlInitUnicodeString(&NormalizedFilePath, CompletionContext->NormalizedFilePath);

                                // 로그 전송 처리 ( 지연된 Create ) 
                                EDR::LogSender::function::FilesystemLog(
                                    CompletionContext->ProcessId,
                                    CompletionContext->timestamp,
                                    Action,
                                    &NormalizedFilePath,
                                    NULL,
                                    SHA256
                                );
                            }*/

                            PFLT_GENERIC_WORKITEM FltWorkItem = (PFLT_GENERIC_WORKITEM)FltAllocateGenericWorkItem();
                            if (FltWorkItem)
                            {
                                EDR::MiniFilter::resource::PHASH_WORK_ITEM_CONTEXT_DETAILS FltWorkItem_CTX = (EDR::MiniFilter::resource::PHASH_WORK_ITEM_CONTEXT_DETAILS)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::MiniFilter::resource::HASH_WORK_ITEM_CONTEXT_DETAILS), FLT_WORKITEM_CTX_ALLOC_TAG);
                                if (FltWorkItem_CTX)
                                {
                                    FltWorkItem_CTX->ProcessId = CompletionContext->ProcessId;
                                    FltWorkItem_CTX->timestamp = CompletionContext->timestamp;
                                    FltWorkItem_CTX->Action = Action; // switch 문에서 결정된 Action
                                    FltWorkItem_CTX->Instance = FltObjects->Instance;
                                    FltWorkItem_CTX->FileObject = FltObjects->FileObject;
                                    FltWorkItem_CTX->NormalizedFilePath = CompletionContext->NormalizedFilePath;

                                    // Instance 참조카운트 증가하여 WorkItem에서 사용할 수 있도록 함.
                                    FltObjectReference(FltWorkItem_CTX->Instance);
                                    ObReferenceObject(FltWorkItem_CTX->FileObject);

                                    if (NT_SUCCESS(FltQueueGenericWorkItem(
                                        FltWorkItem,               // 전달할 item 객체
                                        EDR::MiniFilter::resource::gFilterHandle,      // 현재 필터 핸들
                                        EDR::MiniFilter::POST::FltWorkItem::FltWorkItemThread,     // 실행할 함수
                                        DelayedWorkQueue,           // 큐 우선순위
                                        (PVOID)FltWorkItem_CTX                        // Context 
                                    )))
                                    {
                                        // success
                                        is_success_workitem = TRUE;
                                    }
                                }
                                else
                                {
                                    FltFreeGenericWorkItem(FltWorkItem);
                                }
                            }
                            
                        }
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }

                if (CompletionContext)
                {
                    // 파일명 해제
                    if (!is_success_workitem)
                    {
                        if(CompletionContext->NormalizedFilePath)
                            ExFreePoolWithTag(CompletionContext->NormalizedFilePath, PretoPost_CTX_ALLOC_TAG); 
                    }
                    


                    // CTX 해제
                    ExFreePoolWithTag(CompletionContext, PretoPost_CTX_ALLOC_TAG);
                }
                
                return FLT_POSTOP_FINISHED_PROCESSING;
            }
        }
        namespace PRE
        {
            extern "C" FLT_PREOP_CALLBACK_STATUS
                PRE_filter_Handler(
                    PFLT_CALLBACK_DATA Data,
                    PCFLT_RELATED_OBJECTS FltObjects,
                    EDR::MiniFilter::resource::PPretoPost_CTX* CompletionContext
                )
            {
                if (CompletionContext)
                    *CompletionContext = NULL;

                UNREFERENCED_PARAMETER(FltObjects);

                HANDLE ProcessId = (HANDLE)FltGetRequestorProcessId(Data);
                ULONG64 Nano_Timestamp = EDR::Util::Timestamp::Get_LocalTimestamp_Nano();


                // 시스템 프로세스 제외
                if (PsIsSystemProcess(FltGetRequestorProcess(Data)))
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;

                // AGENT Usermode Process는 제외
                if( !EDR::Util::Shared::USER_AGENT::ProcessId || EDR::Util::Shared::USER_AGENT::ProcessId == ProcessId)
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;

                /*
                if (Data->Iopb->Parameters.Create.Options & FILE_DIRECTORY_FILE) {
                    // 폴더
                }
                else {
                    // 파일
                }*/

                ULONG32 VolumeSerialNumber = 0;
                helper::Get_VolumeSerialNumber(Data, &VolumeSerialNumber); // 패시브 레벨이 아니면 호출안함

                // 파일 확인
                PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
                helper::Is_File_with_Get_File_Info(Data, &nameInfo);
                if (!nameInfo)
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                PUNICODE_STRING NormalizedFilePath = &nameInfo->Name;

                // 파일 액션
                EDR::EventLog::Enum::FileSystem::Filesystem_enum Action = (EDR::EventLog::Enum::FileSystem::Filesystem_enum)0;

                /*
                * 
                * 
                * [ WARNING ]
                * if >= APC ? MUP FILE BSOD !!!@!#!#@!$@#%#
                * 
                ULONG64 FileSize = 0;
                if( !helper::Get_FileSize(FltObjects->Instance, FltObjects->FileObject, &FileSize) )
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                */
                
                FLT_PREOP_CALLBACK_STATUS ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

                // if rename, valid
                PUNICODE_STRING RenameFilePath = NULL;

                // if got filesha256
                

                /*
                * 
                * 
                *  [ WARNING !!!!!!!! ]
                *   VERY POOR PERFORMANCE to hash sha256 here ( in every LEVEL )
                *  안해!!! 파일 삭제 전략으로 진행해야함
                * PRE단에서 아무리 파일 해시가 가능한들, 성능 저하가 급격함.
                * 
                * 
                // SHA256
                CHAR SHA256[SHA256_String_Byte_Length] = { 0 };
                ULONG64 FILESIZE = 0;
                if( !helper::Get_FileSHA256(FltObjects->Instance, FltObjects->FileObject, (PCHAR)SHA256, &FILESIZE )  )
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                    */
                //debug_log("SHA256: %s  +=====+ FILESIZE: %llu \n", SHA256, FILESIZE);
                

                switch (Data->Iopb->MajorFunction)
                {
                case IRP_MJ_CREATE:
                {
                    
                    /*
                        IRP_MJ_CREATE시 에는 파일 상호작용을 위한 직전이므로, 이때 파일 해시를 구한다.
                    */
                    {
                        /*
                            0. Action
                        */
                        /* 알 수 없음 => POST에서 확인 */

                        /*
                        * 
                        * 1. 파일 해싱 구하는 방법
                        * 
                        * IRP_MJ_CREATE일 때 캐치
                        * 
                            IRP_MJ_CREATE시 무조건 POST 핸들러 콜백호출하도록 한다.
                        */
                        EDR::MiniFilter::resource::PPretoPost_CTX PRE_to_POST_CTX = (EDR::MiniFilter::resource::PPretoPost_CTX)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::MiniFilter::resource::PretoPost_CTX), PretoPost_CTX_ALLOC_TAG);
                        RtlZeroMemory(PRE_to_POST_CTX, sizeof(EDR::MiniFilter::resource::PretoPost_CTX));

                        // IRP_MJ_CREATE (파일 오픈 등 파일핸들 딱 얻을 시점 )에서 POST호출 요청하여 파일 해싱 안전하게 처리
                        PRE_to_POST_CTX->NormalizedFilePath = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, NormalizedFilePath->MaximumLength + sizeof(WCHAR), PretoPost_CTX_ALLOC_TAG);
                        RtlZeroMemory(PRE_to_POST_CTX->NormalizedFilePath, NormalizedFilePath->MaximumLength + sizeof(WCHAR));

                        RtlCopyMemory(PRE_to_POST_CTX->NormalizedFilePath, NormalizedFilePath->Buffer, NormalizedFilePath->MaximumLength);
                        *CompletionContext = PRE_to_POST_CTX;

                        /*
                             2. POST에 넘길 정보 저장
                        */
                        //PRE_to_POST_CTX->Action = Action;
                        PRE_to_POST_CTX->ProcessId = ProcessId;
                        PRE_to_POST_CTX->timestamp = Nano_Timestamp;

                        



                        ReturnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
                    }
                    
                    

                    

                    goto CleanUp; // 바로 리턴 ( POST에서 후속작업 ) 
                }
                case IRP_MJ_READ:
                {
                    Action = EDR::EventLog::Enum::FileSystem::read;
                    break;
                }
                case IRP_MJ_WRITE:
                {
                    Action = EDR::EventLog::Enum::FileSystem::write;
                    break;
                }
                case IRP_MJ_SET_INFORMATION:
                {
                    // 1. 파일 이름 변경 필터링
                    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
                        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx)
                    {
                        Action = EDR::EventLog::Enum::FileSystem::rename;
                        PFILE_RENAME_INFORMATION renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
                        if (!renameInfo)
                            return ReturnStatus;

                        RenameFilePath = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING) + renameInfo->FileNameLength+sizeof(WCHAR), 'Renm');
                        if(!RenameFilePath)
                            return ReturnStatus;
                        RtlZeroMemory(RenameFilePath, sizeof(UNICODE_STRING) + renameInfo->FileNameLength + sizeof(WCHAR));
                        RenameFilePath->Length = (USHORT)renameInfo->FileNameLength;
                        RenameFilePath->MaximumLength = (USHORT)renameInfo->FileNameLength+sizeof(WCHAR);
                        RenameFilePath->Buffer = (PWCH)((PUCHAR)RenameFilePath + sizeof(UNICODE_STRING));
                        RtlCopyMemory(RenameFilePath->Buffer, renameInfo->FileName, renameInfo->FileNameLength);

                    }
                    // 2. 파일 삭제 확인
                    else if (
                        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation ||
                        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformationEx)
                    {
                        Action = EDR::EventLog::Enum::FileSystem::remove;
                        PFILE_DISPOSITION_INFORMATION delInfo = (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
                        if (!delInfo && !delInfo->DeleteFile)
                            return ReturnStatus;
                    }
                    else
                    {
                        // 알수없음
                        return ReturnStatus;
                    }
                    break;
                }
                default:
                    return ReturnStatus;
                }

                EDR::LogSender::function::FilesystemLog(
                    ProcessId,
                    Nano_Timestamp,
                    Action,
                    NormalizedFilePath,
                    RenameFilePath,
                    NULL
                );



            CleanUp:
                {
                    if (RenameFilePath)
                        ExFreePoolWithTag(RenameFilePath, 'Renm');


                    return ReturnStatus;
                }
            }
        }
        namespace helper
        {
            /*
            * 
            * 미니필터에서 ZwCreate,Open,Read등은 옳지 않다. [ POST ] 로 콜백호출하여 Flt.. 함수로 미니필터 전용 API 로 파일 해싱하던가  바이너리 작업 해야함
            BOOLEAN Get_FileSHA256_by_FILEPATH(
                PUNICODE_STRING FilePath,
                PSIZE_T FileSize,
                PCHAR Allocated_SHA256
            )
            {

                return NT_SUCCESS(Util::File::Read::ReadFileAndComputeSHA256(
                    *FilePath,
                    Allocated_SHA256,
                    FileSize
                ));
            }*/

            // 파일여부 확인 및 이름 정보 추출 ( 추출시 "Relase_Is_File_with_Get_File_Info" 호출 필수
            BOOLEAN Is_File_with_Get_File_Info(
                PFLT_CALLBACK_DATA Input_Data, // 핸들러에서 얻은 정보
                PFLT_FILE_NAME_INFORMATION* Output_fileNameInfo // 정보 반환 (아니면 그대로 냅둔 ) 
            )
            {
                if (Output_fileNameInfo == NULL) return FALSE;

                // 1차 관문 -- 유저모드에 의한 요청인지 체크
                if (Input_Data->RequestorMode != UserMode) return FALSE;

                // 2차 관문 -- 파일이라면 아래와 같은 API가 성공함 
                if (FltGetFileNameInformation(Input_Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, Output_fileNameInfo) != STATUS_SUCCESS)
                    return FALSE;

                // 파일 이름 추출
                if (FltParseFileNameInformation(*Output_fileNameInfo) != STATUS_SUCCESS) {

                    FltReleaseFileNameInformation(*Output_fileNameInfo);
                    return FALSE;
                }

                return TRUE;
            }


            VOID Relase_Is_File_with_Get_File_Info(PFLT_FILE_NAME_INFORMATION fileNameInfo)
            {
                if (fileNameInfo)
                    FltReleaseFileNameInformation(fileNameInfo);
            }

            // 파일 고유 Index값 가져오기
            NTSTATUS Get_FileReferenceNumber(
                _In_ PFLT_INSTANCE Instance,
                _In_ PFILE_OBJECT FileObject,
                _Out_ PULONG64 pFileReferenceNumber
            )
            {
                PAGED_CODE(); // 이 함수는 PASSIVE_LEVEL에서만 호출되어야 함

                NTSTATUS status;
                FILE_INTERNAL_INFORMATION fileInternalInfo;
                ULONG bytesReturned;

                if (pFileReferenceNumber == NULL) {
                    return STATUS_INVALID_PARAMETER;
                }
                *pFileReferenceNumber = 0; // 출력 파라미터 초기화

                // FltQueryInformationFile을 사용하여 파일의 내부 정보를 요청
                status = FltQueryInformationFile(
                    Instance,
                    FileObject,
                    &fileInternalInfo,
                    sizeof(fileInternalInfo),
                    FileInternalInformation, // 정보 클래스 지정
                    &bytesReturned
                );

                if (!NT_SUCCESS(status)) {
                    return status;
                }

                // 성공 시, IndexNumber 필드(이것이 FRN)를 복사
                *pFileReferenceNumber = fileInternalInfo.IndexNumber.QuadPart;

                return STATUS_SUCCESS;
            }

            // 파일 사이즈 구하기
            _Success_(return == TRUE)
                BOOLEAN Get_FileSize(
                    _In_ PFLT_INSTANCE Instance,
                    _In_ PFILE_OBJECT FileObject,
                    _Inout_ ULONG64 * Out_FIleSize
                )
            {
                if (!Instance || !FileObject || !Out_FIleSize) return FALSE;
                NTSTATUS status;
                FILE_STANDARD_INFORMATION fileInfo = { 0 };

                // 1. 파일 크기 가져오기
                status = FltQueryInformationFile(
                    Instance,
                    FileObject,
                    &fileInfo,
                    sizeof(FILE_STANDARD_INFORMATION),
                    FileStandardInformation,
                    NULL
                );
                if (!NT_SUCCESS(status)) {
                    return FALSE;
                }

                *Out_FIleSize = fileInfo.EndOfFile.QuadPart;

                return TRUE;
            }

            // 볼륨 넘버얻기
            NTSTATUS Get_VolumeSerialNumber
            (
                _In_ PFLT_CALLBACK_DATA Data,
                ULONG32 * OutVolumeSerial
            )
            {
                if (!Data)
                    return STATUS_INVALID_PARAMETER_1;

                if (!OutVolumeSerial)
                    return STATUS_INVALID_PARAMETER_2;

                PAGED_CODE();

                NTSTATUS status;
                PFLT_VOLUME Volume = nullptr;

                // 1. FLT_VOLUME 얻기
                status = FltGetVolumeFromInstance(Data->Iopb->TargetInstance, &Volume);
                if (!NT_SUCCESS(status) || !Volume)
                    return status;

                // 2. 볼륨 정보 가져오기
                PFLT_INSTANCE instance = Data->Iopb->TargetInstance;
                IO_STATUS_BLOCK iosb = { 0 };
                FILE_FS_VOLUME_INFORMATION volumeInfo = { 0 };

                status = FltQueryVolumeInformation(
                    instance,
                    &iosb,
                    &volumeInfo,
                    sizeof(volumeInfo),
                    FileFsVolumeInformation
                );
                if (!NT_SUCCESS(status))
                    return status;

                *OutVolumeSerial = volumeInfo.VolumeSerialNumber;

                return STATUS_SUCCESS;
            }

            BOOLEAN Get_FileSHA256(
                _In_ PFLT_INSTANCE Instance,
                _In_ PFILE_OBJECT FileObject,
                _Inout_ PCHAR Inout_SHABuffer, // 최소 SHA256_BINARY_LENGTH 바이트
                _Out_ ULONG64* Out_FileSize
            )
            {
                if (!Instance || !FileObject || !Inout_SHABuffer || !Out_FileSize)
                    return FALSE;

                NTSTATUS status;
                FILE_STANDARD_INFORMATION fileInfo = { 0 };
                PUCHAR chunkBuffer = NULL;
                LARGE_INTEGER fileSize = { 0 };
                LARGE_INTEGER byteOffset = { 0 };
                ULONG bytesRead = 0;
                BOOLEAN bResult = FALSE;

                *Out_FileSize = 0;

                // 1. 파일 크기 조회
                status = FltQueryInformationFile(
                    Instance,
                    FileObject,
                    &fileInfo,
                    sizeof(FILE_STANDARD_INFORMATION),
                    FileStandardInformation,
                    NULL
                );
                if (!NT_SUCCESS(status))
                    return FALSE;

                fileSize = fileInfo.EndOfFile;
                *Out_FileSize = fileSize.QuadPart;

                if (fileSize.QuadPart == 0)
                {
                    RtlZeroMemory(Inout_SHABuffer, SHA256_BINARY_LENGTH);
                    return TRUE;
                }

                // 2. IRQL에 따라 청크 크기 결정
                ULONG chunkSize = 0;
                KIRQL irql = KeGetCurrentIrql();
                POOL_FLAGS poolType;

                if (irql <= PASSIVE_LEVEL)
                {
                    chunkSize = 2 * 1024 * 1024; // 2MB
                    poolType = POOL_FLAG_PAGED;
                }
                else
                {
                    chunkSize = 16 * 1024; // 16KB
                    poolType = POOL_FLAG_NON_PAGED;
                }

                chunkBuffer = (PUCHAR)ExAllocatePool2(poolType, chunkSize, 'fBuH');
                if (!chunkBuffer)
                    return FALSE;

                // 3. SHA-256 초기화
                EDR::Util::Hash::SHA256::with_UpdateMode::SHA256_UPDATE_CTX ctx;
                if (!EDR::Util::Hash::SHA256::with_UpdateMode::SHA256_Initialize(&ctx))
                    goto cleanup;

                // 4. 청크 단위 읽기 및 점진 해시
                while (byteOffset.QuadPart < fileSize.QuadPart)
                {
                    ULONG toRead = (ULONG)min(chunkSize, fileSize.QuadPart - byteOffset.QuadPart);

                    status = FltReadFile(
                        Instance,
                        FileObject,
                        &byteOffset,
                        toRead,
                        chunkBuffer,
                        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                        &bytesRead,
                        NULL,
                        NULL
                    );

                    if (!NT_SUCCESS(status) || bytesRead == 0)
                        goto cleanup;

                    if (!EDR::Util::Hash::SHA256::with_UpdateMode::SHA256_Update(&ctx, chunkBuffer, bytesRead))
                        goto cleanup;

                    byteOffset.QuadPart += bytesRead;
                }

                // 5. 최종 SHA-256 계산
                if (EDR::Util::Hash::SHA256::with_UpdateMode::SHA256_Finish(&ctx, (PCHAR)Inout_SHABuffer, SHA256_String_Byte_Length) != SHA256_String_Byte_Length)
                    goto cleanup;

                bResult = TRUE;

            cleanup:
                if (chunkBuffer)
                    ExFreePoolWithTag(chunkBuffer, 'fBuH');

                return bResult;
            }

        }

	}
}




extern "C" VOID
InstanceTeardownCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Reason);

    

}

extern "C" NTSTATUS
InstanceSetupCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    return STATUS_SUCCESS;
}