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
            { IRP_MJ_CREATE, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_CREATE_NAMED_PIPE, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_CLOSE, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_READ, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_WRITE, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_QUERY_INFORMATION, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_SET_INFORMATION, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_QUERY_EA, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_SET_EA, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_FLUSH_BUFFERS, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_QUERY_VOLUME_INFORMATION, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_SET_VOLUME_INFORMATION, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_DIRECTORY_CONTROL, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_FILE_SYSTEM_CONTROL, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_DEVICE_CONTROL, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_INTERNAL_DEVICE_CONTROL, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            //{ IRP_MJ_SHUTDOWN, 0, NULL, NULL }, // No post-operation callback
            { IRP_MJ_LOCK_CONTROL, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_CLEANUP, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_CREATE_MAILSLOT, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_QUERY_SECURITY, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_SET_SECURITY, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_POWER, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_SYSTEM_CONTROL, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_DEVICE_CHANGE, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_QUERY_QUOTA, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_SET_QUOTA, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
            { IRP_MJ_PNP, 0, Handler::PRE::PRE_filter_Handler, Handler::POST::POST_filter_Handler },
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
                Callback_s,                      // Operation callbacks // ���� �ڵ鷯�� IRP�� �迭�� ���ε� ����
                NULL,                           // MiniFilterUnload
                InstanceSetupCallback,          // InstanceSetup
                NULL,                           // InstanceQueryTeardown
                InstanceTeardownCallback,       // InstanceTeardownStart
                InstanceTeardownCallback,       // InstanceTeardownComplete
                NULL,                           // GenerateFileName
                NULL,                           // GenerateDestinationFileName
                NULL                            // NormalizeNameComponent
            };

            status = FltRegisterFilter(DriverObject, &FilterRegistration, &resource::gFilterHandle);  // ���
            if (NT_SUCCESS(status)) {

                status = FltStartFiltering(resource::gFilterHandle); // ����
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
                resource::gFilterHandle = NULL; // �ڵ��� NULL�� �����Ͽ� �� �̻� ������ ������ ǥ��
            }
        }

        namespace POST
        {
            extern "C" FLT_POSTOP_CALLBACK_STATUS
                POST_filter_Handler(
                    PFLT_CALLBACK_DATA Data,
                    PCFLT_RELATED_OBJECTS FltObjects,
                    PVOID CompletionContext,
                    FLT_POST_OPERATION_FLAGS Flags
                )
            {
                UNREFERENCED_PARAMETER(FltObjects);
                UNREFERENCED_PARAMETER(Data);
                UNREFERENCED_PARAMETER(CompletionContext);
                UNREFERENCED_PARAMETER(Flags);
                return FLT_POSTOP_FINISHED_PROCESSING;
            }
        }
        namespace PRE
        {
            extern "C" FLT_PREOP_CALLBACK_STATUS
                PRE_filter_Handler(
                    PFLT_CALLBACK_DATA Data,
                    PCFLT_RELATED_OBJECTS FltObjects,
                    PVOID* CompletionContext
                )
            {
                UNREFERENCED_PARAMETER(FltObjects);

                HANDLE ProcessId = (HANDLE)FltGetRequestorProcessId(Data);
                ULONG64 Nano_Timestamp = EDR::Util::Timestamp::Get_LocalTimestamp_Nano();




                // �ý��� ���μ��� ����
                if (PsIsSystemProcess(FltGetRequestorProcess(Data)))
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;

                // AGENT Usermode Process�� ����
                if( EDR::IOCTL::IOCTL_PROCESSING::resource::User_AGENT_ProcessId == ProcessId)
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;

                // ���� Ȯ��
                PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
                helper::Is_File_with_Get_File_Info(Data, &nameInfo);
                if (!nameInfo)
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                PUNICODE_STRING NormalizedFilePath = &nameInfo->Name;

                // ���� �׼�
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
                


                // if rename, valid
                PUNICODE_STRING RenameFilePath = NULL;

                /*
                * 
                * 
                *  [ WARNING !!!!!!!! ]
                *   VERY POOR PERFORMANCE to hash sha256 here ( in every LEVEL )
                *  ����!!! ���� ���� �������� �����ؾ���
                * PRE�ܿ��� �ƹ��� ���� �ؽð� �����ѵ�, ���� ���ϰ� �ް���.
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
                    Action = EDR::EventLog::Enum::FileSystem::create;
                    break;
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
                    // 1. ���� �̸� ���� ���͸�
                    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
                        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx)
                    {
                        Action = EDR::EventLog::Enum::FileSystem::rename;
                        PFILE_RENAME_INFORMATION renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
                        if (!renameInfo)
                            return FLT_PREOP_SUCCESS_NO_CALLBACK;

                        RenameFilePath = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING) + renameInfo->FileNameLength+sizeof(WCHAR), 'Renm');
                        if(!RenameFilePath)
                            return FLT_PREOP_SUCCESS_NO_CALLBACK;
                        RtlZeroMemory(RenameFilePath, sizeof(UNICODE_STRING) + renameInfo->FileNameLength + sizeof(WCHAR));
                        RenameFilePath->Length = (USHORT)renameInfo->FileNameLength;
                        RenameFilePath->MaximumLength = (USHORT)renameInfo->FileNameLength+sizeof(WCHAR);
                        RenameFilePath->Buffer = (PWCH)((PUCHAR)RenameFilePath + sizeof(UNICODE_STRING));
                        RtlCopyMemory(RenameFilePath->Buffer, renameInfo->FileName, renameInfo->FileNameLength);

                    }
                    // 2. ���� ���� Ȯ��
                    else if (
                        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation ||
                        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformationEx)
                    {
                        Action = EDR::EventLog::Enum::FileSystem::remove;
                        PFILE_DISPOSITION_INFORMATION delInfo = (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
                        if (!delInfo && !delInfo->DeleteFile)
                            return FLT_PREOP_SUCCESS_NO_CALLBACK;
                    }
                    else
                    {
                        // �˼�����
                        return FLT_PREOP_SUCCESS_NO_CALLBACK;
                    }
                    break;
                }
                default:
                    break;
                }

                EDR::LogSender::function::FilesystemLog(
                    ProcessId,
                    Nano_Timestamp,
                    Action,
                    NormalizedFilePath,
                    RenameFilePath
                );

                if (RenameFilePath)
                    ExFreePoolWithTag(RenameFilePath, 'Renm');

                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
        }
        namespace helper
        {

            // ���Ͽ��� Ȯ�� �� �̸� ���� ���� ( ����� "Relase_Is_File_with_Get_File_Info" ȣ�� �ʼ�
            BOOLEAN Is_File_with_Get_File_Info(
                PFLT_CALLBACK_DATA Input_Data, // �ڵ鷯���� ���� ����
                PFLT_FILE_NAME_INFORMATION* Output_fileNameInfo // ���� ��ȯ (�ƴϸ� �״�� ���� ) 
            )
            {
                if (Output_fileNameInfo == NULL) return FALSE;

                // 1�� ���� -- ������忡 ���� ��û���� üũ
                if (Input_Data->RequestorMode != UserMode) return FALSE;

                // 2�� ���� -- �����̶�� �Ʒ��� ���� API�� ������ 
                if (FltGetFileNameInformation(Input_Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, Output_fileNameInfo) != STATUS_SUCCESS)
                    return FALSE;

                // ���� �̸� ����
                if (FltParseFileNameInformation(*Output_fileNameInfo) != STATUS_SUCCESS) {

                    FltReleaseFileNameInformation(*Output_fileNameInfo);
                    return FALSE;
                }

                return TRUE;
            }


            VOID Relase_Is_File_with_Get_File_Info(PFLT_FILE_NAME_INFORMATION fileNameInfo)
            {
                if(fileNameInfo)
                    FltReleaseFileNameInformation(fileNameInfo);
            }


            // ���� ������ ���ϱ�
            _Success_(return == TRUE)
            BOOLEAN Get_FileSize(
                _In_ PFLT_INSTANCE Instance,
                _In_ PFILE_OBJECT FileObject,
                _Inout_ ULONG64* Out_FIleSize
            )
            {
                if (!Instance || !FileObject || !Out_FIleSize) return FALSE;
                NTSTATUS status;
                FILE_STANDARD_INFORMATION fileInfo = { 0 };

                // 1. ���� ũ�� ��������
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

            _Success_(return == TRUE)
            BOOLEAN Get_FileSHA256(
                _In_ PFLT_INSTANCE Instance,
                _In_ PFILE_OBJECT FileObject,
                _Inout_ PCHAR Inout_SHABuffer, // �ּ� SHA256_BINARY_LENGTH ����Ʈ
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

                // 1. ���� ũ�� ��ȸ
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

                // 2. IRQL�� ���� ûũ ũ�� ����
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

                // 3. SHA-256 �ʱ�ȭ
                EDR::Util::Hash::SHA256::with_UpdateMode::SHA256_UPDATE_CTX ctx;
                if (!EDR::Util::Hash::SHA256::with_UpdateMode::SHA256_Initialize(&ctx))
                    goto cleanup;

                // 4. ûũ ���� �б� �� ���� �ؽ�
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

                // 5. ���� SHA-256 ���
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