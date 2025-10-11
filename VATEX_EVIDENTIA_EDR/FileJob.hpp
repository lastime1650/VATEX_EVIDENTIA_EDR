#ifndef FILEJOB_H
#define FILEJOB_H

#include <ntifs.h>

#define FILEJOB_ALLOC_TAG 'FiLe'
#define FILE_REMOVE_CHUNK_SIZE 4096

namespace EDR
{
	namespace Util
	{
		namespace File
		{
			namespace Read
			{
				NTSTATUS ReadFile( _In_ UNICODE_STRING FilePath, _Inout_ PUCHAR* FileBytes, _Inout_ SIZE_T* FileBytesSize);
				NTSTATUS Get_FIleSIze(PUNICODE_STRING FilePath, SIZE_T* FIleSIze);
				NTSTATUS ReadFileAndComputeSHA256(
					_In_ UNICODE_STRING FilePath,
					_Inout_ PCHAR OutSHAHexBuffer,
					_Out_ SIZE_T* FileSize
				);
			}

			namespace Remove
			{
				NTSTATUS RemoveFile(_In_ PUNICODE_STRING FilePath);
			}
			
			VOID Release_File(PUCHAR FileBytes);
		}
	}
}


#endif