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

				Registry_CompleteNameLog, // Registry - CompleteName

				ImageLoad,
				ObRegisterCallback

			};

			namespace FileSystem
			{
				// Filesystem
				enum Filesystem_enum
				{
					create = 1,
					remove,
					rename,
					read,
					write
				};
			}


			namespace Registry
			{
				//Registry
				enum Registry_enum
				{
					RegNtPreDeleteKey = 0,
					RegNtPreSetValueKey = 1,
					RegNtPreDeleteValueKey = 2,
					RegNtPreSetInformationKey = 3,
					RegNtPreRenameKey = 4,

					RegNtPreQueryKey = 7,
					RegNtPreQueryValueKey = 8,
					RegNtPreQueryMultipleValueKey = 9,
					RegNtPreCreateKeyEx = 26,
					RegNtPreOpenKeyEx = 28
				};
			}

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
			namespace Process
			{
				// Process_Create
				struct EventLog_Process_Create
				{
					struct EventLog_Header header;

					struct
					{
						HANDLE Parent_ProcessId;
						CHAR CommandLine[4096];

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
				};
			}

			namespace ImageLoad
			{
				// ImageLoad
				struct EventLog_ImageLoad
				{
					struct EventLog_Header header;

					struct
					{
						CHAR ImagePathAnsi[4096];

						struct
						{
							ULONG64 Parent_Process_exe_size;
							CHAR Parent_Process_exe_SHA256[65];
						}post;

					}body;
				};
			}

			namespace Network
			{
				// Network
				struct EventLog_Process_Network
				{
					struct EventLog_Header header;

					struct
					{

						ULONG32 ProtocolNumber;
						BOOLEAN is_INBOUND;
						ULONG32 PacketSize;

						CHAR LOCAL_IP[16];
						ULONG32 LOCAL_PORT;

						CHAR REMOTE_IP[16];
						ULONG32 REMOTE_PORT;

						ULONG32 ifindex; // 유저모드에서 인터페이스 이름 추출 필요

						struct
						{
							CHAR InterfaceName[256];
						}post;

					}body;

				};
			}


			namespace FileSystem
			{
				// Filesystem
				// Filesystem
				struct EventLog_Process_Filesystem
				{
					struct EventLog_Header header;

					struct
					{

						/*
							비동기 후속처리
						*/
						struct
						{
							ULONG64 FileSize;
						}post;

						Enum::FileSystem::Filesystem_enum Action;
						CHAR FilePath[4096];

						struct
						{
							BOOLEAN is_valid;
							CHAR RenameFilePath[4096];
						}rename;

					}body;

				};
			}

			namespace Registry
			{
				// Registry
				struct EventLog_Process_Registry_CompleteorObjectNameLog
				{
					struct EventLog_Header header;

					struct
					{

						Enum::Registry::Registry_enum FunctionName;
						CHAR Name[4096];


					}body;

				};
			}

			namespace ObRegisterCallback
			{
				// ObRegisterCallback
				struct EventLog_Process_ObRegisterCallback
				{
					struct EventLog_Header header;

					struct
					{
						BOOLEAN is_CreateHandleInformation; // if TRUE, CreateHandle / else DuplicateHandleInformation
						HANDLE Target_ProcessId;
						CHAR TargetProcess_Path[4096];
						ULONG32 DesiredAccess; // 접근권한
					}body;

				};
			}


			// ProcessAccess
			// ObRegisterCallback으로 해당 프로세스가 다른 프로세스에 영향이 가는지 확인

			struct EventLog_Process_ProcessAccess
			{
				struct EventLog_Header header;

				struct
				{


					HANDLE SourceProcessId;
					HANDLE TargetProcessId;


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