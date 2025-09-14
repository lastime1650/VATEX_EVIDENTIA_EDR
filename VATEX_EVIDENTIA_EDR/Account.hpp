#ifndef WIN_ACCOUNT_H
#define WIN_ACCOUNT_H

#include <ntifs.h>

#define PROCESS_SID_ALLOC 'ACNT'

namespace EDR
{
	namespace Util
	{
		namespace Account
		{
			namespace SID
			{
				NTSTATUS Get_PROCESS_SID(HANDLE ProcessId, _Inout_ PUNICODE_STRING out_SID);
				VOID Release_PROCESS_SID(PUNICODE_STRING SID);
			}

		}
	}
	
}

#endif