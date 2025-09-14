#ifndef FILEJOB_H
#define FILEJOB_H

#include <ntifs.h>

#define FILEJOB_ALLOC_TAG 'FiLe'

namespace EDR
{
	namespace Util
	{
		namespace File
		{
			namespace Read
			{
				NTSTATUS ReadFile( _In_ UNICODE_STRING FilePath, _Inout_ PUCHAR* FileBytes, _Inout_ SIZE_T* FileBytesSize);
			}
			
			VOID Release_File(PUCHAR FileBytes);
		}
	}
}


#endif