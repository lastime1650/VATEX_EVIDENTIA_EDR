#ifndef LOGSENDER_HPP
#define LOGSENDER_HPP

#include "util.hpp"
#include "EventLog.hpp"
#include "APC.hpp"
#include "IOCTL.hpp"

namespace EDR
{

	namespace LogSender
	{

		BOOLEAN INITIALIZE();
		VOID CleanUp();


		namespace resource
		{
			#define MAXIMUM_SLIST_NODE_SIZE 65535
			extern SLIST_HEADER g_ListHead;
			extern BOOLEAN is_consume_working;
			extern volatile ULONG64 g_NodeCount;  // 노드 개수 카운터

			typedef struct _LOG_NODE {
				SLIST_ENTRY Entry;
				ULONG64 Type;
				PVOID   UserSpace;
				SIZE_T  UserSpaceSize;
			} LOG_NODE, * PLOG_NODE;

			namespace Produce
			{
				BOOLEAN ProducdeLogData(ULONG64 Type, PVOID UserSpace, SIZE_T UserSpaceSize);
			}
			namespace Consume
			{
				extern "C" VOID Consume(PVOID nothing);
				void CleanUpNodes();
			}

		}

		namespace LogPost
		{
			namespace WorkItem_method
			{
				#define WorkItem_LogALLOC 'WRKi'
				typedef struct _WORK_CONTEXT {
					WORK_QUEUE_ITEM Item;

					PVOID LogEvent;
				} WORK_CONTEXT, * PWORK_CONTEXT;
				extern "C" VOID POST_Workitem_method(PVOID ctx);
			}
			namespace SystemThread_method
			{
				#define LogALLOC 'Log'
				#define LogPostCtxALLOC 'LogP'
				struct ctx
				{
					EDR::EventLog::Enum::EventLog_Enum type;
					ULONG64 NanoTimestamp;

					PVOID log;
				};
				extern "C" VOID POST_SystemThread_method(PVOID CTX);
			}
		}

		namespace function
		{
			BOOLEAN ProcessCreateLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				HANDLE Parent_ProcessId
			);

			BOOLEAN ProcessTerminateLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp
			);

			BOOLEAN ImageLoadLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				PCUNICODE_STRING ImagePath
			);

			BOOLEAN FilesystemLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				EDR::EventLog::Enum::FileSystem::Filesystem_enum FsEnum,
				UNICODE_STRING* Normalized_FilePath, // \harddisk..\,,\ ( DOS 파티션 알파벳이 아님 )

				UNICODE_STRING* To_Renmae_FilePath // if NULL< not Rename.
				
			);

			BOOLEAN NetworkLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				ULONG32 ProtocolNumber,
				BOOLEAN is_INBOUND,
				ULONG32 PacketSize,

				PUCHAR LOCAL_IP,
				ULONG32 LOCAL_IP_StrSIze,
				ULONG32 LOCAL_PORT,

				PUCHAR REMOTE_IP,
				ULONG32 REMOTE_IP_StrSIze,
				ULONG32 REMOTE_PORT
			);

			// Registry
			BOOLEAN Registry_by_CompleteorObjectNameLog(
				EDR::EventLog::Enum::Registry::Registry_enum KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp,
				PUNICODE_STRING CompleteName
			);
			BOOLEAN Registry_by_SetNameLog( // rename 포함
				EDR::EventLog::Enum::Registry::Registry_enum KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp, 
				PUNICODE_STRING Object, PUNICODE_STRING Name
			);

			//ObRegisterCallback
			BOOLEAN ObRegisterCallbackLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				BOOLEAN is_CreateHandleInformation,
				ULONG32 DesiredAccess,
				HANDLE Target_ProcessId
			);
		}
		
		namespace helper
		{
			BOOLEAN CHAR_to_FILESIZE(PCHAR FIlePathBuffer, ULONG32 FIlePathBufferSize, SIZE_T* FileSize);
			BOOLEAN CHAR_to_HASH(PCHAR FIlePathBuffer, ULONG32 FIlePathBufferSize, PCHAR out_HASHBUFFER, SIZE_T* out_FileSize);

			// UNICODE_STRING to CHAR
			BOOLEAN UNICODE_to_CHAR(PUNICODE_STRING input, CHAR* Buffer, SIZE_T BUfferSIze);

			BOOLEAN Process_to_HASH(HANDLE ProcessId, CHAR* out_ImagePathNameBuffer, SIZE_T in_ImagePathNameBufferSIze, SIZE_T* out_ImageFileSize, CHAR* out_SHA256Buffer, SIZE_T SHA256BufferSize);
			BOOLEAN FilePath_to_HASH(PUNICODE_STRING UnicodeImagePath, SIZE_T* out_ImageFileSize, CHAR* inout_SHA256Buffer, SIZE_T SHA256BufferSize);

			// PID to CHAR
			BOOLEAN Process_to_CHAR(HANDLE ProcessHandle, CHAR* Buffer, SIZE_T BUfferSIze);
			
			// SID copy to CHAR
			BOOLEAN SID_to_CHAR(HANDLE ProcessId, CHAR* Buffer, SIZE_T BUfferSIze);
		}

	}
}

#endif