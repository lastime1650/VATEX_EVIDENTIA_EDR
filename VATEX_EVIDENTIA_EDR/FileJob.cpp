#include "FileJob.hpp"
#include "HASH.hpp"
#include <intrin.h>
namespace EDR
{
	namespace Util
	{
		namespace File
		{
            namespace Remove
            {
                // File 삭제.

                /*
                    [ 로직 흐름 ]
                    // 1. 파일을 연다
                    // 2. 0x00으로 싹다 덮어쓴다.
                    // 3. 삭제. (DeleteFile)
                */
                NTSTATUS RemoveFile(_In_ PUNICODE_STRING FilePath)
                {
                    NTSTATUS status = STATUS_UNSUCCESSFUL;
                    HANDLE fileHandle = NULL;
                    OBJECT_ATTRIBUTES objAttr;
                    IO_STATUS_BLOCK ioStatus = { 0 };
                    FILE_STANDARD_INFORMATION fileInfo = { 0 };

                    // 열기
                    InitializeObjectAttributes(&objAttr,
                        FilePath,
                        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                        NULL,
                        NULL);

                    status = ZwOpenFile(&fileHandle,
                        GENERIC_READ | GENERIC_WRITE | DELETE,
                        &objAttr,
                        &ioStatus,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
                    if (!NT_SUCCESS(status))
                        return status;

                    // 크기 확인
                    status = ZwQueryInformationFile(
                        fileHandle,
                        &ioStatus,
                        &fileInfo,
                        sizeof(fileInfo),
                        FileStandardInformation
                    );
                    ULONG64 get_fileSize = fileInfo.EndOfFile.QuadPart;

                    // 0x00 으로 덮어쓰기
                    if (get_fileSize)
                    {
                        UCHAR zeroBuf[FILE_REMOVE_CHUNK_SIZE];
                        RtlZeroMemory(zeroBuf, FILE_REMOVE_CHUNK_SIZE); // 0x00

                        LARGE_INTEGER offset;
                        for (offset.QuadPart = 0; offset.QuadPart < get_fileSize; offset.QuadPart += FILE_REMOVE_CHUNK_SIZE) {
                            ULONG toWrite = (ULONG)min(FILE_REMOVE_CHUNK_SIZE, fileInfo.EndOfFile.QuadPart - (ULONG64)offset.QuadPart);
                            status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus, zeroBuf, toWrite, &offset, NULL);
                            if (!NT_SUCCESS(status)) break;
                        }
                    }

                    // 삭제 조치
                    FILE_DISPOSITION_INFORMATION dispInfo = { TRUE };
                    status = ZwSetInformationFile(
                        fileHandle,
                        &ioStatus,
                        &dispInfo,
                        sizeof(dispInfo),
                        FileDispositionInformation
                    );


                    ZwClose(fileHandle);
                    return status;

                }
            }

			namespace Read
			{


                NTSTATUS Get_FIleSIze(PUNICODE_STRING FilePath, SIZE_T* FIleSIze)
                {
                    NTSTATUS status = STATUS_UNSUCCESSFUL;
                    HANDLE fileHandle = NULL;
                    OBJECT_ATTRIBUTES objAttr;
                    IO_STATUS_BLOCK ioStatus = { 0 };
                    FILE_STANDARD_INFORMATION fileInfo = { 0 };

                    // 열기
                    InitializeObjectAttributes(&objAttr,
                        FilePath,
                        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                        NULL,
                        NULL);

                    status = ZwOpenFile(&fileHandle,
                        GENERIC_READ,
                        &objAttr,
                        &ioStatus,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
                    if (!NT_SUCCESS(status))
                        return status;

                    // 파일 사이즈 조회
                    status = ZwQueryInformationFile(
                        fileHandle,
                        &ioStatus,
                        &fileInfo,
                        sizeof(fileInfo),
                        FileStandardInformation
                    );
                    if (!NT_SUCCESS(status)) {
                        ZwClose(fileHandle);
                        return status;
                    }

                    *FIleSIze = (SIZE_T)fileInfo.EndOfFile.QuadPart;
                    ZwClose(fileHandle);
                    return STATUS_SUCCESS;
                }

                // OutSHAHexBuffer: 최소 SHA_HEX_SIZE 바이트 확보 필요

                #define HASH_CHUNK_SIZE   (5 * 1024 * 1024) // 5MB chunk (원하면 상수 변경 가능)
                NTSTATUS ReadFileAndComputeSHA256(
                    _In_ UNICODE_STRING FilePath,
                     _Inout_ PCHAR OutSHAHexBuffer,
                     _Out_ SIZE_T* FileSize
                )
                {
                    if (!FilePath.Buffer || FilePath.Length == 0)
                        return STATUS_INVALID_PARAMETER_1;
                    if (!OutSHAHexBuffer)
                        return STATUS_INVALID_PARAMETER_2;

                    NTSTATUS status = STATUS_UNSUCCESSFUL;
                    HANDLE fileHandle = NULL;
                    OBJECT_ATTRIBUTES objAttr;
                    IO_STATUS_BLOCK ioStatus = { 0 };
                    FILE_STANDARD_INFORMATION fileInfo = { 0 };
                    PUCHAR chunkBuffer = NULL;
                    SIZE_T chunkSize = HASH_CHUNK_SIZE;
                    SIZE_T totalSize = 0;
                    SIZE_T bytesRemaining = 0;
                    ULONG bytesRead = 0;

                    // 열기
                    InitializeObjectAttributes(&objAttr,
                        &FilePath,
                        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                        NULL,
                        NULL);

                    status = ZwOpenFile(&fileHandle,
                        GENERIC_READ,
                        &objAttr,
                        &ioStatus,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
                    if (!NT_SUCCESS(status))
                        return status;

                    // 파일 사이즈 조회
                    status = ZwQueryInformationFile(
                        fileHandle,
                        &ioStatus,
                        &fileInfo,
                        sizeof(fileInfo),
                        FileStandardInformation
                    );
                    if (!NT_SUCCESS(status)) {
                        ZwClose(fileHandle);
                        return status;
                    }

                    totalSize = (SIZE_T)fileInfo.EndOfFile.QuadPart;
                    *FileSize = totalSize;
                    if (totalSize == 0) {
                        // 빈 파일
                        OutSHAHexBuffer[0] = '\0'; // 초기화 보장
                        ZwClose(fileHandle);
                        return STATUS_SUCCESS;
                    }

                    // chunk buffer 할당 (paged)
                    if (chunkSize > totalSize)
                        chunkSize = totalSize;

                    chunkBuffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, chunkSize, FILEJOB_ALLOC_TAG);
                    if (!chunkBuffer) {
                        ZwClose(fileHandle);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    // SHA 초기화
                    EDR::Util::Hash::SHA256::with_UpdateMode::SHA256_UPDATE_CTX shaCtx = { 0 };
                    if (!EDR::Util::Hash::SHA256::with_UpdateMode::SHA256_Initialize(&shaCtx)) {
                        ExFreePoolWithTag(chunkBuffer, FILEJOB_ALLOC_TAG);
                        ZwClose(fileHandle);
                        return STATUS_INTERNAL_ERROR;
                    }

                    // 순차적으로 읽어가며 해시 업데이트
                    bytesRemaining = totalSize;
                    while (bytesRemaining > 0) {
                        ULONG toRead = (ULONG)min(chunkSize, bytesRemaining);

                        // ZwReadFile: 파일 핸들이 synchronous로 열려 있으므로 ByteOffset == NULL로 순차 읽기
                        status = ZwReadFile(
                            fileHandle,
                            NULL,
                            NULL,
                            NULL,
                            &ioStatus,
                            chunkBuffer,
                            toRead,
                            NULL,
                            NULL
                        );

                        if (status == STATUS_PENDING) {
                            // 동기 핸들로 열었을 때는 보통 Pending이 발생하지 않지만, 안전히 처리
                            status = ZwWaitForSingleObject(fileHandle, FALSE, NULL);
                            // 이후 ioStatus.Status 확인
                            status = ioStatus.Status;
                        }

                        if (!NT_SUCCESS(status)) {
                            // 실패 시 정리
                            EDR::Util::Hash::SHA256::with_UpdateMode::SHA256_Finish(&shaCtx, OutSHAHexBuffer, SHA256_String_Byte_Length); // cleanup inside
                            ExFreePoolWithTag(chunkBuffer, FILEJOB_ALLOC_TAG);
                            ZwClose(fileHandle);
                            return status;
                        }

                        // 실제 읽은 바이트 수
                        bytesRead = (ULONG)ioStatus.Information;
                        if (bytesRead == 0)
                            break;

                        // Update 해시 (bytesRead 만큼)
                        if (!EDR::Util::Hash::SHA256::with_UpdateMode::SHA256_Update(&shaCtx, chunkBuffer, bytesRead)) {
                            EDR::Util::Hash::SHA256::with_UpdateMode::SHA256_Finish(&shaCtx, OutSHAHexBuffer, SHA256_String_Byte_Length);
                            ExFreePoolWithTag(chunkBuffer, FILEJOB_ALLOC_TAG);
                            ZwClose(fileHandle);
                            return STATUS_INTERNAL_ERROR;
                        }

                        bytesRemaining -= bytesRead;
                    }

                    // 최종 해시 문자열 생성
                    ULONG32 hexLen = EDR::Util::Hash::SHA256::with_UpdateMode::SHA256_Finish(&shaCtx, OutSHAHexBuffer, SHA256_String_Byte_Length);
                    // 정리
                    ExFreePoolWithTag(chunkBuffer, FILEJOB_ALLOC_TAG);
                    ZwClose(fileHandle);

                    if (hexLen != SHA256_String_Byte_Length)
                        return STATUS_INTERNAL_ERROR;

                    return STATUS_SUCCESS;
                }
				
				NTSTATUS ReadFile(_In_ UNICODE_STRING FilePath, _Inout_ PUCHAR* FileBytes, _Inout_ SIZE_T* FileBytesSize)
				{
					if (!FilePath.Buffer || !FilePath.Length || !FilePath.MaximumLength)
						return STATUS_INVALID_PARAMETER_1;
					if (!FileBytes)
						return STATUS_INVALID_PARAMETER_2;
					if (!FileBytesSize)
						return STATUS_INVALID_PARAMETER_3;

                    HANDLE filehandle = NULL;
                    OBJECT_ATTRIBUTES objAttr;
                    IO_STATUS_BLOCK ioStatusBlock;

                    // Initialize OBJECT_ATTRIBUTES
                    InitializeObjectAttributes(&objAttr,
                        &FilePath,
                        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                        NULL, NULL);

                    // Open the file
                    NTSTATUS status = ZwOpenFile(&filehandle,
                        GENERIC_READ,
                        &objAttr,
                        &ioStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
                    if (!NT_SUCCESS(status))
                        return status;

                    // Query file size
                    FILE_STANDARD_INFORMATION fileInfo;
                    status = ZwQueryInformationFile(
                        filehandle,
                        &ioStatusBlock,
                        &fileInfo,
                        sizeof(fileInfo),
                        FileStandardInformation);
                    if (!NT_SUCCESS(status)) {
                        ZwClose(filehandle);
                        return status;
                    }

                    if (fileInfo.EndOfFile.QuadPart == 0) {
                        *FileBytes = NULL;
                        *FileBytesSize = 0;
                        ZwClose(filehandle);
                        return STATUS_SUCCESS;
                    }

                    // Allocate memory
                    SIZE_T fileSize = (SIZE_T)fileInfo.EndOfFile.QuadPart;
                    PUCHAR buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, fileSize, FILEJOB_ALLOC_TAG);
                    if (!buffer) {
                        ZwClose(filehandle);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    // Read file
                    status = ZwReadFile(filehandle,
                        NULL,
                        NULL,
                        NULL,
                        &ioStatusBlock,
                        buffer,
                        (ULONG)fileSize,
                        NULL,
                        NULL);

                    ZwClose(filehandle);

                    if (!NT_SUCCESS(status)) {
                        Release_File(buffer);
                        return status;
                    }

                    *FileBytes = buffer;
                    *FileBytesSize = fileSize;

                    return STATUS_SUCCESS;

				}
			}

			VOID Release_File(PUCHAR FileBytes)
			{
				if (FileBytes)
					ExFreePoolWithTag(FileBytes, FILEJOB_ALLOC_TAG);
			}
		}
	}
}

