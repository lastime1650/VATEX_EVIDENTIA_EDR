#ifndef PROCESS_UTIL__H
#define PROCESS_UTIL__H

#include <ntifs.h>


#define ImagePath_ALLOC_TAG 'ImPh'
namespace EDR
{
	namespace Util
	{
		namespace Process
		{
			namespace Handle
			{
				NTSTATUS LookupProcessHandlebyProcessId(HANDLE ProcessId, HANDLE* ProcessHandle);
				VOID ReleaseLookupProcessHandlebyProcessId(HANDLE ProcessHandle);
			}

			namespace ImagePath
			{

				NTSTATUS LookupProcessAbsoluteImagePathbyProcessHandle(HANDLE ProcessHandle, PUNICODE_STRING* output_unicode);
				VOID ReleaseLookupProcessAbsoluteImagePathbyProcessHandle(PUNICODE_STRING Input_unicode);
			}


		}
	}
}

#endif