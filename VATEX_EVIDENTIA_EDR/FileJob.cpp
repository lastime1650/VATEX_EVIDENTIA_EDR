#include "FileJob.hpp"

namespace EDR
{
	namespace Util
	{
		namespace File
		{
			namespace Read
			{
				
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

