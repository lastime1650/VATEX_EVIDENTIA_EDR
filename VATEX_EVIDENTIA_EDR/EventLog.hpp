#ifndef EVENT_LOG_HPP
#define EVENT_LOG_HPP

#include <ntifs.h>

namespace EDR
{
	namespace EvenLog
	{
			
		namespace Enum
		{
			enum EventLog_Enum
			{
				Process_Create = 1,
				Process_Terminate,

				Network,

				Filesystem
					
			};
		}

		namespace Struct
		{
			// 모든 이벤트의 헤더
			struct EventLog_Header
			{
				Enum::EventLog_Enum Type;

				HANDLE ProcessId;
				ULONG64 NanoTimestamp;

				struct
				{
					CHAR SID[256];
					
				}Account;

			};

			// Process_Create
			struct EventLog_Process_Create
			{
				struct EventLog_Header header;

				HANDLE Parent_ProcessId;


				CHAR Self_Process_exe_path[4096];
				ULONG64 Self_Process_exe_size;

				CHAR Parent_Process_exe_path[4096];
				ULONG64 Self_Process_exe_size;

				
			};
			// Process_Terminate
			// Network
			// Filesystem


		}

	}
	
}


#endif