#ifndef EVENT_LOG_HPP
#define EVENT_LOG_HPP

#include "util.hpp"

namespace EDR
{
	
	namespace EventLog
	{
		namespace Enum
		{
			enum EventLog_Enum
			{
				Process_Create = 1,
				Process_Terminate,

				Network,

				Filesystem,
				ImageLoad

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
				CHAR Version[256];
			};

			// Process_Create
			struct EventLog_Process_Create
			{
				struct EventLog_Header header;

				struct
				{
					HANDLE Parent_ProcessId;

					/*
						[POST]
							비동기 후속 작업 요구
					*/
					struct
					{
						CHAR SID[256];


						ULONG64 Self_Process_exe_size;
						CHAR Self_Process_exe_SHA256[65];
						CHAR Self_Process_exe_path[4096];

						ULONG64 Parent_Process_exe_size;
						CHAR Parent_Process_exe_SHA256[65];
						CHAR Parent_Process_exe_path[4096];

					}post;
				}body;
			};

			// Process_Terminate
			struct EventLog_Process_Terminate
			{
				struct EventLog_Header header;

				CHAR ImagePathAnsi[4096];

				struct
				{
					ULONG64 Parent_Process_exe_size;
					CHAR Parent_Process_exe_SHA256[65];
				}post;
			};

			// ImageLoad
			struct EventLog_Process_ImageLoad
			{
				struct EventLog_Header header;

				struct
				{

					/*
						[POST]
							비동기 후속 작업 요구
					*/
					struct
					{
						CHAR SID[256];

						CHAR ImagePath[4096];
						CHAR ImageSHA256[65];
						SIZE_T ImageSize;

					}post;

				}body;

			};

			// Network
			struct EventLog_Process_Network
			{
				struct EventLog_Header header;

				struct
				{

					/*
						[POST]
							비동기 후속 작업 요구
					*/
					ULONG32 ProtocolNumber;
					BOOLEAN is_INBOUND;
					ULONG32 PacketSize;

					CHAR LOCAL_IP[16];
					ULONG32 LOCAL_PORT;

					CHAR REMOTE_IP[16];
					ULONG32 REMOTE_PORT;

					UCHAR PacketBinary[65535];
					ULONG32 PacketBinSize;

				}body;

			};

			// Filesystem
			struct EventLog_Process_Filesystem
			{
				struct EventLog_Header header;

				struct
				{

					/*
						[POST]
							비동기 후속 작업 요구
					*/
					struct
					{
						CHAR SID[256];

					}post;

				}body;

			};

		}

		namespace HandlerLog
		{
			struct HandlerLog_s
			{
				Enum::EventLog_Enum type;
				unsigned char* logData;
			};
		}
	}

}


#endif