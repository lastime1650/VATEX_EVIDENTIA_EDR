#ifndef SHARED_HPP
#define SHARED_HPP

#include <ntifs.h>

namespace EDR
{
	namespace Util
	{
		namespace Shared
		{
			namespace USER_AGENT
			{
				extern HANDLE ProcessId;
				extern HANDLE ProcessHandle;
			}


			namespace API_HOOK
			{
				extern PCHAR HookDllPath;
			}
		}
	}
}


#endif