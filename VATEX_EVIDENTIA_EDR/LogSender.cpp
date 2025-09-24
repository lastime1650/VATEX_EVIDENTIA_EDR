#include "LogSender.hpp"

namespace EDR
{
	namespace LogSender
	{
		ERESOURCE g_Resource;

		BOOLEAN INITIALIZE()
		{
			PAGED_CODE();

			LogPost::is_LogPostWorking = TRUE;

			// 로그 큐 스레드 실행
			HANDLE THREAD = NULL;
			NTSTATUS status = PsCreateSystemThread(
				&THREAD,
				THREAD_ALL_ACCESS,
				NULL,
				NULL,
				NULL,
				(PKSTART_ROUTINE)EDR::LogSender::LogPost::SystemThread_method::POST_SystemThread_method,
				NULL
			);
			if (!NT_SUCCESS(status) || !THREAD)
				return FALSE;

			// Detach
			ZwClose(THREAD);

			return TRUE;
		}
		VOID CleanUp()
		{
			resource::Consume::CleanUpNodes();
			LogPost::CleanUpLogNodes();
		}

		namespace resource
		{
			SLIST_HEADER g_ListHead;

			namespace Produce
			{
				BOOLEAN ProducdeLogData(ULONG64 Type, PVOID UserSpace, SIZE_T UserSpaceSize)
				{

					USHORT NodeCount = QueryDepthSList(&g_ListHead);
					if (NodeCount >= MAXIMUM_SLIST_NODE_SIZE)
						return FALSE;



					PLOG_NODE node = (PLOG_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LOG_NODE), LogALLOC);
					if (!node)
						return false;

					node->Type = Type;
					node->UserSpace = UserSpace;
					node->UserSpaceSize = UserSpaceSize;
					InterlockedPushEntrySList(&g_ListHead, &node->Entry); // 노드 추가

					return  TRUE;
				}
			}
			namespace Consume
			{
				BOOLEAN Consume(_Out_ PVOID* AllocatedUser, _Out_ ULONG64* Size)
				{
					if (!AllocatedUser || !Size)
						return FALSE;

					*AllocatedUser = NULL;
					*Size = 0;

					PSLIST_ENTRY firstEntry = InterlockedFlushSList(&g_ListHead); // 모든 노드 엔트리 플러시 ( 원자적으로 다 가져옴 ) 
					if (!firstEntry)
						return FALSE;

					BOOLEAN RETURNBOOL = FALSE;

					// 크기 계산
					PSLIST_ENTRY currentEntry = firstEntry;
					USHORT TotalNodeCount = 0;
					ULONG64 ALLOCATED_SIZE = 0;
					while (currentEntry != NULL) {


						PLOG_NODE node = CONTAINING_RECORD(currentEntry, LOG_NODE, Entry);

						// 1. 
						TotalNodeCount++;

						// 2.
						ALLOCATED_SIZE += sizeof(PVOID);

						currentEntry = currentEntry->Next;
					}

					// 할당
					PUCHAR ALLBUFF = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, ALLOCATED_SIZE, LogALLOC);
					if (!ALLBUFF)
					{
						goto CleanUp;
					}

					// 복사
					currentEntry = firstEntry;
					ULONG64 offset = 0;
					while (currentEntry != NULL) {
						PLOG_NODE node = CONTAINING_RECORD(currentEntry, LOG_NODE, Entry);
						RtlCopyMemory(
							ALLBUFF + offset,
							&node->UserSpace,
							sizeof(node->UserSpace)
						);
						offset += sizeof(node->UserSpace);
						currentEntry = currentEntry->Next;
					}



					// 유저에 복사
					HANDLE UserAgent_ProcessHandle = EDR::Util::Shared::USER_AGENT::ProcessHandle;
					if (!UserAgent_ProcessHandle)
						goto CleanUp;
					HANDLE UserAgent_ProcessId = EDR::Util::Shared::USER_AGENT::ProcessId;
					if (!UserAgent_ProcessId)
						goto CleanUp;


					PVOID AllocatedUserSpace = NULL;
					SIZE_T AllocatedUserSpaceSize = ALLOCATED_SIZE;

					// 유저공간에 할당
					EDR::Util::UserSpace::Memory::AllocateMemory(
						UserAgent_ProcessHandle,
						&AllocatedUserSpace,
						&AllocatedUserSpaceSize
					);
					if (!AllocatedUserSpace)
						goto CleanUp;

					RETURNBOOL = EDR::Util::UserSpace::Memory::Copy(UserAgent_ProcessId, AllocatedUserSpace, ALLBUFF, ALLOCATED_SIZE);
					if (!RETURNBOOL)
					{
						EDR::Util::UserSpace::Memory::FreeMemory(
							UserAgent_ProcessHandle,
							AllocatedUserSpace,
							AllocatedUserSpaceSize
						);
						goto CleanUp;
					}



					*AllocatedUser = AllocatedUserSpace;
					*Size = ALLOCATED_SIZE;

					RETURNBOOL = TRUE;

				CleanUp:
					{

						if (ALLBUFF)
							ExFreePoolWithTag(ALLBUFF, LogALLOC);

						for (ULONG64 i = 0; i < TotalNodeCount; i++)
						{
							PSLIST_ENTRY entry_node = InterlockedPopEntrySList(&g_ListHead);
							if (!entry_node)
								break;
							PLOG_NODE node = CONTAINING_RECORD(entry_node, LOG_NODE, Entry);
							ExFreePoolWithTag(node, LogALLOC);
						}
						return RETURNBOOL;
					}
				}



				void CleanUpNodes()
				{
					// 남은 노드 엔트리 모두 할당해제
					USHORT NodeCount = QueryDepthSList(&g_ListHead);
					if (NodeCount)
					{
						for (ULONG64 node_count = 0; node_count < NodeCount; node_count++)
						{
							PSLIST_ENTRY entry_node = InterlockedPopEntrySList(&g_ListHead);  // 노드 개수 원자적으로 1씩 감소
							if (!entry_node)
								break;

							PLOG_NODE node = CONTAINING_RECORD(entry_node, LOG_NODE, Entry);
							HANDLE APC_Target_ProcessHandle = EDR::Util::Shared::USER_AGENT::ProcessHandle;

							if (APC_Target_ProcessHandle)
							{
								EDR::Util::UserSpace::Memory::FreeMemory(
									APC_Target_ProcessHandle,
									node->UserSpace,
									node->UserSpaceSize
								);
							}

							ExFreePoolWithTag(node, LogALLOC);
						}
					}

				}

			}
		}

		namespace LogPost
		{
			/*
			namespace WorkItem_method
			{
				extern "C" VOID POST_Workitem_method(PVOID ctx)
				{
					

					if (!ctx)
						return;

					PWORK_CONTEXT workitem_ctx = (PWORK_CONTEXT)ctx;
					if (!workitem_ctx->LogEvent)
					{
						ExFreePoolWithTag(workitem_ctx, WorkItem_LogALLOC);
						return;
					}


					HANDLE thread = NULL;
					PsCreateSystemThread(
						&thread,
						THREAD_ALL_ACCESS,
						NULL,
						NULL,
						NULL,
						(PKSTART_ROUTINE)LogPost::SystemThread_method::POST_SystemThread_method,
						workitem_ctx->LogEvent
					);
					if (thread)
					{
						ZwClose(thread); // Detach
					}

					ExFreePoolWithTag(workitem_ctx, WorkItem_LogALLOC);
				}
			}*/

			BOOLEAN is_LogPostWorking = false;
			SLIST_HEADER g_LogPostListHead;

			VOID CleanUpLogNodes()
			{
				is_LogPostWorking = false;
				// 남은 노드 엔트리 모두 할당해제
				USHORT NodeCount = QueryDepthSList(&g_LogPostListHead);
				if (NodeCount)
				{
					for (ULONG64 node_count = 0; node_count < NodeCount; node_count++)
					{
						PSLIST_ENTRY entry_node = InterlockedPopEntrySList(&g_LogPostListHead);  // 노드 개수 원자적으로 1씩 감소
						if (!entry_node)
							break;

						PLOG_QUEUE_NODE node = CONTAINING_RECORD(entry_node, LOG_QUEUE_NODE, Entry);

						ExFreePoolWithTag(node, Log_SLIST_ALLOC);
					}
				}
			}

			BOOLEAN LogPut(PVOID log)
			{
				USHORT NodeCount = QueryDepthSList(&g_LogPostListHead);
				if (NodeCount >= MAXIMUM_SLIST_NODE_SIZE)
					return FALSE;



				PLOG_QUEUE_NODE node = (PLOG_QUEUE_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LOG_QUEUE_NODE), Log_SLIST_ALLOC);
				if (!node)
					return false;

				node->log = log;
				InterlockedPushEntrySList(&g_LogPostListHead, &node->Entry); // 노드 추가

				return  TRUE;
			}

			BOOLEAN LogGet(_Out_ PVOID* log)
			{
				if (!log)
					return FALSE;

				*log = NULL;

				PSLIST_ENTRY Log_Entry = InterlockedPopEntrySList(&g_LogPostListHead); // 원자적으로 1개 가져옴
				if (!Log_Entry)
					return FALSE;

				PLOG_QUEUE_NODE node = CONTAINING_RECORD(Log_Entry, LOG_QUEUE_NODE, Entry);
				if (!node)
					return FALSE;

				*log = node->log; // log가져옴
				if (!*log)
					return FALSE;

				ExFreePoolWithTag(node, Log_SLIST_ALLOC);

				return TRUE;
			}

			namespace SystemThread_method
			{
				extern "C" VOID POST_SystemThread_method(PVOID no_used)
				{
					UNREFERENCED_PARAMETER(no_used);

					PAGED_CODE();

					while (is_LogPostWorking)
					{

						// 로그 가져오기
						PVOID CTX = NULL;
						if (!LogGet(&CTX))
						{
							// 100ms 대기
							LARGE_INTEGER interval;
							interval.QuadPart = -1000000LL; // 100ms, 단위: 100ns, 음수 = relative time
							KeDelayExecutionThread(KernelMode, FALSE, &interval);
							continue;
						}


						NTSTATUS status = STATUS_UNSUCCESSFUL;
						EDR::EventLog::Struct::EventLog_Header* logHeader = (EDR::EventLog::Struct::EventLog_Header*)CTX;

						PVOID AllocatedUserSpace = NULL;
						SIZE_T AllocatedUserSpaceSize = 0;
						SIZE_T logSize = 0;

						// APC타겟 유저(USER AGENT 프로세스) PID 유효체크
						HANDLE APC_Target_ProcessHandle = EDR::Util::Shared::USER_AGENT::ProcessHandle;
						if (!APC_Target_ProcessHandle)
							goto CleanUp;
						HANDLE APC_Target_ProcessId = EDR::Util::Shared::USER_AGENT::ProcessId;
						if (!APC_Target_ProcessId)
							goto CleanUp;



						switch (logHeader->Type)
						{
						case  EDR::EventLog::Enum::Filesystem:
						{


							EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem* log = (EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem*)CTX;
							logSize = sizeof(EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem);

							EDR::Util::helper::CHAR_to_FILESIZE(
								log->body.FilePath,
								sizeof(log->body.FilePath),
								&log->body.post.FileSize
							);

							AllocatedUserSpaceSize = logSize;
							// User 공간 Allocate
							EDR::Util::UserSpace::Memory::AllocateMemory(
								APC_Target_ProcessHandle,
								&AllocatedUserSpace,
								&AllocatedUserSpaceSize
							);

							if (!AllocatedUserSpace)
								goto CleanUp;

							break;
						}
						case EDR::EventLog::Enum::Network:
						{
							EDR::EventLog::Struct::Network::EventLog_Process_Network* log = (EDR::EventLog::Struct::Network::EventLog_Process_Network*)CTX;
							logSize = sizeof(EDR::EventLog::Struct::Network::EventLog_Process_Network);


							// ifindex -> InterfaceName(ansi)
							EDR::Util::helper::GetInterfaceNameFromIndex_Ansi(
								(ULONG)log->body.ifindex,
								log->body.post.InterfaceName,
								sizeof(log->body.post.InterfaceName)
							);


							AllocatedUserSpaceSize = logSize;
							// User 공간 Allocate
							EDR::Util::UserSpace::Memory::AllocateMemory(
								APC_Target_ProcessHandle,
								&AllocatedUserSpace,
								&AllocatedUserSpaceSize
							);

							if (!AllocatedUserSpace)
								goto CleanUp;

							break;
						}
						case EDR::EventLog::Enum::Process_Terminate:
						{
							logSize = sizeof(EDR::EventLog::Struct::Process::EventLog_Process_Terminate);
							AllocatedUserSpaceSize = logSize;
							// User 공간 Allocate
							EDR::Util::UserSpace::Memory::AllocateMemory(
								APC_Target_ProcessHandle,
								&AllocatedUserSpace,
								&AllocatedUserSpaceSize
							);

							if (!AllocatedUserSpace)
								goto CleanUp;
							break;
						}
						case EDR::EventLog::Enum::ImageLoad:
						{
							EDR::EventLog::Struct::ImageLoad::EventLog_ImageLoad* log = (EDR::EventLog::Struct::ImageLoad::EventLog_ImageLoad*)CTX;
							logSize = sizeof(EDR::EventLog::Struct::ImageLoad::EventLog_ImageLoad);

							UNICODE_STRING ImagePath;
							EDR::Util::String::Ansi2Unicode::ANSI_to_UnicodeString((PCHAR)log->body.ImagePathAnsi, (ULONG32)(strlen(log->body.ImagePathAnsi) + 1), &ImagePath);

							EDR::Util::helper::FilePath_to_HASH(
								&ImagePath,
								&log->body.post.Parent_Process_exe_size,
								log->body.post.Parent_Process_exe_SHA256,
								sizeof(log->body.post.Parent_Process_exe_SHA256)
							);

							EDR::Util::String::Ansi2Unicode::Release_ANSI_to_UnicodeString(&ImagePath);


							AllocatedUserSpaceSize = logSize;
							// User 공간 Allocate
							EDR::Util::UserSpace::Memory::AllocateMemory(
								APC_Target_ProcessHandle,
								&AllocatedUserSpace,
								&AllocatedUserSpaceSize
							);

							if (!AllocatedUserSpace)
								goto CleanUp;

							break;
						}
						case EDR::EventLog::Enum::Process_Create:
						{
							EDR::EventLog::Struct::Process::EventLog_Process_Create* log = (EDR::EventLog::Struct::Process::EventLog_Process_Create*)CTX;
							logSize = sizeof(EDR::EventLog::Struct::Process::EventLog_Process_Create);

							/*
								SID 추출
							*/
							if (!EDR::Util::helper::SID_to_CHAR(log->header.ProcessId, (PCHAR)log->body.post.SID, sizeof(log->body.post.SID)))
								goto CleanUp;

							/*
								Self 프로세스 이미지경로/파일사이즈/해시값 경로구하기
							*/
							EDR::Util::helper::Process_to_HASH(
								log->header.ProcessId,

								// Self Process EXE ImagePath
								log->body.post.Self_Process_exe_path,
								sizeof(log->body.post.Self_Process_exe_path),

								// Self Process EXE ImageSize
								&log->body.post.Self_Process_exe_size,

								// Self Process EXE SHA256
								log->body.post.Self_Process_exe_SHA256,
								sizeof(log->body.post.Self_Process_exe_SHA256)
							);

							/*
								Parent 프로세스 이미지경로/파일사이즈/해시값 경로구하기
							*/
							EDR::Util::helper::Process_to_HASH(
								log->body.Parent_ProcessId,

								// Parent Process EXE ImagePath
								log->body.post.Parent_Process_exe_path,
								sizeof(log->body.post.Parent_Process_exe_path),

								// Parent Process EXE ImageSize
								&log->body.post.Parent_Process_exe_size,

								// Parent Process EXE SHA256
								log->body.post.Parent_Process_exe_SHA256,
								sizeof(log->body.post.Parent_Process_exe_SHA256)
							);

							/*
								Parent 프로세스 실행파일(1) 및 SHA256(2) 구하기
							*/

							AllocatedUserSpaceSize = logSize;
							// User 공간 Allocate
							EDR::Util::UserSpace::Memory::AllocateMemory(
								APC_Target_ProcessHandle,
								&AllocatedUserSpace,
								&AllocatedUserSpaceSize
							);

							if (!AllocatedUserSpace)
								goto CleanUp;

							break;
						}
						default:
						{
							goto CleanUp;
						}
						}


						// Copy to User 공간s
						EDR::Util::UserSpace::Memory::Copy(APC_Target_ProcessId, AllocatedUserSpace, CTX, logSize);


						// Producing Log
						EDR::LogSender::resource::Produce::ProducdeLogData((ULONG64)logHeader->Type, AllocatedUserSpace, logSize);

					CleanUp:
						{
							if (CTX)
								ExFreePoolWithTag(CTX, LogALLOC);
						}
					}

					
				}

				
			}
		}

		namespace function
		{

			BOOLEAN ProcessCreateLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				HANDLE Parent_ProcessId,
				PCUNICODE_STRING CommandLine
			) {
				PAGED_CODE();





				EDR::EventLog::Struct::Process::EventLog_Process_Create* log = (EDR::EventLog::Struct::Process::EventLog_Process_Create*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::EventLog::Struct::Process::EventLog_Process_Create), LogALLOC);
				if (!log)
					return FALSE;
				RtlZeroMemory(log, sizeof(EDR::EventLog::Struct::Process::EventLog_Process_Create));
				log->header.Type = EDR::EventLog::Enum::Process_Create;
				log->header.ProcessId = ProcessId;
				log->header.NanoTimestamp = NanoTimestamp;
				EDR::Util::SysVersion::GetSysVersion(log->header.Version, sizeof(log->header.Version));


				log->body.Parent_ProcessId = Parent_ProcessId;
				EDR::Util::helper::UNICODE_to_CHAR(
					(PUNICODE_STRING)CommandLine,
					log->body.CommandLine,
					sizeof(log->body.CommandLine)
				);


				// 큐
				LogPost::LogPut(log);

				return TRUE;
					
			}

			BOOLEAN ProcessTerminateLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp
			) {
				PAGED_CODE();

				EDR::EventLog::Struct::Process::EventLog_Process_Terminate* log = (EDR::EventLog::Struct::Process::EventLog_Process_Terminate*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::EventLog::Struct::Process::EventLog_Process_Terminate), LogALLOC);
				if (!log)
					return FALSE;
				RtlZeroMemory(log, sizeof(EDR::EventLog::Struct::Process::EventLog_Process_Terminate));
				log->header.Type = EDR::EventLog::Enum::Process_Terminate;
				log->header.ProcessId = ProcessId;
				log->header.NanoTimestamp = NanoTimestamp;
				EDR::Util::SysVersion::GetSysVersion(log->header.Version, sizeof(log->header.Version));

				LogPost::SystemThread_method::POST_SystemThread_method((PVOID)log); // Terminate 작업은 헤더만 포함하므로 바로 호출작업 (블로킹 작업(FileI/O) 따로 없음)

				return TRUE;
			}

			BOOLEAN ImageLoadLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				PCUNICODE_STRING ImagePath
			) {
				PAGED_CODE();

				EDR::EventLog::Struct::ImageLoad::EventLog_ImageLoad* log = (EDR::EventLog::Struct::ImageLoad::EventLog_ImageLoad*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::EventLog::Struct::ImageLoad::EventLog_ImageLoad), LogALLOC);
				if (!log)
					return FALSE;
				RtlZeroMemory(log, sizeof(EDR::EventLog::Struct::ImageLoad::EventLog_ImageLoad));
				log->header.Type = EDR::EventLog::Enum::ImageLoad;
				log->header.ProcessId = ProcessId;
				log->header.NanoTimestamp = NanoTimestamp;
				EDR::Util::SysVersion::GetSysVersion(log->header.Version, sizeof(log->header.Version));


				EDR::Util::helper::UNICODE_to_CHAR(
					(PUNICODE_STRING)ImagePath,
					log->body.ImagePathAnsi,
					sizeof(log->body.ImagePathAnsi)
				);


				// 큐
				LogPost::LogPut(log);

				return TRUE;
			}

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
				ULONG32 REMOTE_PORT,

				ULONG32 NetworkInterfaceIndex
			)
			{
				// ~ DISPATCH LEVEL
				// work-item 필수
				EDR::EventLog::Struct::Network::EventLog_Process_Network* log = (EDR::EventLog::Struct::Network::EventLog_Process_Network*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::EventLog::Struct::Network::EventLog_Process_Network), LogALLOC);
				if (!log)
					return FALSE;
				RtlZeroMemory(log, sizeof(EDR::EventLog::Struct::Network::EventLog_Process_Network));
				log->header.Type = EDR::EventLog::Enum::Network;
				log->header.ProcessId = ProcessId;
				log->header.NanoTimestamp = NanoTimestamp;
				EDR::Util::SysVersion::GetSysVersion(log->header.Version, sizeof(log->header.Version));

				// Body
				log->body.ProtocolNumber = ProtocolNumber;
				log->body.is_INBOUND = is_INBOUND;
				log->body.PacketSize = PacketSize;
				log->body.ifindex = NetworkInterfaceIndex;

				

				RtlCopyMemory(
					log->body.LOCAL_IP,
					LOCAL_IP,
					LOCAL_IP_StrSIze
				);
				log->body.LOCAL_PORT = LOCAL_PORT;

				RtlCopyMemory(
					log->body.REMOTE_IP,
					REMOTE_IP,
					REMOTE_IP_StrSIze
				);
				log->body.REMOTE_PORT = REMOTE_PORT;


				// 큐
				LogPost::LogPut(log);
					

				return TRUE;
			}

			BOOLEAN FilesystemLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				EDR::EventLog::Enum::FileSystem::Filesystem_enum FsEnum,
				UNICODE_STRING* Normalized_FilePath,

				UNICODE_STRING* To_Renmae_FilePath, // if NULL< not Rename.
				PCHAR SHA256

			) {
				// < = APC_LEVEL
				// work-item 필수
				EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem* log = (EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem), LogALLOC);
				if (!log)
					return FALSE;
				RtlZeroMemory(log, sizeof(EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem));
				log->header.Type = EDR::EventLog::Enum::Filesystem;
				log->header.ProcessId = ProcessId;
				log->header.NanoTimestamp = NanoTimestamp;
				EDR::Util::SysVersion::GetSysVersion(log->header.Version, sizeof(log->header.Version));

				// Body
				log->body.Action = FsEnum;
				EDR::Util::helper::UNICODE_to_CHAR(Normalized_FilePath, log->body.FilePath, sizeof(log->body.FilePath));
				//RtlCopyMemory(log->body.SHA256, SHA256, SHA256_STRING_LENGTH); // SHA256

				//if rename
				if (To_Renmae_FilePath)
				{
					log->body.rename.is_valid = TRUE;
					EDR::Util::helper::UNICODE_to_CHAR(To_Renmae_FilePath, log->body.rename.RenameFilePath, sizeof(log->body.rename.RenameFilePath));
					
				}
				else
					log->body.rename.is_valid = FALSE;
				
				// if SHA256
				if (SHA256)
				{
					log->body.sha256.is_valid = TRUE;
					RtlCopyMemory(log->body.sha256.SHA256, SHA256, SHA256_STRING_LENGTH); // SHA256
				}
				else
					log->body.sha256.is_valid = FALSE;

				// 큐
				LogPost::LogPut(log);

				return TRUE;
			}

			// Registry
			BOOLEAN Registry_by_CompleteorObjectNameLog(
				PCHAR KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp,
				PUNICODE_STRING CompleteName
			)
			{
				// ~ APC_LEVEL
					// work-item 필수
				EDR::EventLog::Struct::Registry::EventLog_Process_Registry_CompleteorObjectNameLog* log = (EDR::EventLog::Struct::Registry::EventLog_Process_Registry_CompleteorObjectNameLog*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::EventLog::Struct::Registry::EventLog_Process_Registry_CompleteorObjectNameLog), LogALLOC);
				if (!log)
					return FALSE;
				RtlZeroMemory(log, sizeof(EDR::EventLog::Struct::Registry::EventLog_Process_Registry_CompleteorObjectNameLog));
				log->header.Type = EDR::EventLog::Enum::Registry_CompleteNameLog;
				log->header.ProcessId = ProcessId;
				log->header.NanoTimestamp = NanoTimestamp;
				EDR::Util::SysVersion::GetSysVersion(log->header.Version, sizeof(log->header.Version));

				memcpy(log->body.FunctionName, KeyClass, strlen(KeyClass));
				EDR::Util::helper::UNICODE_to_CHAR(CompleteName, log->body.Name, sizeof(log->body.Name));

				// 큐
				LogPost::LogPut(log);

				return TRUE;
			}
			BOOLEAN Registry_by_OldNewNameLog(
				PCHAR KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp,
				PUNICODE_STRING Name, PUNICODE_STRING Old, PUNICODE_STRING New
			)
			{
				// ~ APC_LEVEL
					// work-item 필수
				EDR::EventLog::Struct::Registry::EventLog_Process_Registry_OldNewNameLog* log = (EDR::EventLog::Struct::Registry::EventLog_Process_Registry_OldNewNameLog*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::EventLog::Struct::Registry::EventLog_Process_Registry_OldNewNameLog), LogALLOC);
				if (!log)
					return FALSE;
				RtlZeroMemory(log, sizeof(EDR::EventLog::Struct::Registry::EventLog_Process_Registry_OldNewNameLog));
				log->header.Type = EDR::EventLog::Enum::Registry_CompleteNameLog;
				log->header.ProcessId = ProcessId;
				log->header.NanoTimestamp = NanoTimestamp;
				EDR::Util::SysVersion::GetSysVersion(log->header.Version, sizeof(log->header.Version));




				memcpy(log->body.FunctionName, KeyClass, strlen(KeyClass));
				EDR::Util::helper::UNICODE_to_CHAR(Name, log->body.Name, sizeof(log->body.Name));
				EDR::Util::helper::UNICODE_to_CHAR(Old, log->body.OldName, sizeof(log->body.OldName));
				EDR::Util::helper::UNICODE_to_CHAR(New, log->body.NewName, sizeof(log->body.NewName));


				// 큐
				LogPost::LogPut(log);

				return TRUE;
			}

			//ObRegisterCallback
			BOOLEAN ObRegisterCallbackLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				BOOLEAN is_CreateHandleInformation,
				ULONG32 DesiredAccess,
				HANDLE Target_ProcessId
			)
			{
				// ~ APC_LEVEL
					// work-item 필수
				EDR::EventLog::Struct::ObRegisterCallback::EventLog_Process_ObRegisterCallback* log = (EDR::EventLog::Struct::ObRegisterCallback::EventLog_Process_ObRegisterCallback*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::EventLog::Struct::ObRegisterCallback::EventLog_Process_ObRegisterCallback), LogALLOC);
				if (!log)
					return FALSE;
				RtlZeroMemory(log, sizeof(EDR::EventLog::Struct::ObRegisterCallback::EventLog_Process_ObRegisterCallback));
				log->header.Type = EDR::EventLog::Enum::ObRegisterCallback;
				log->header.ProcessId = ProcessId;
				log->header.NanoTimestamp = NanoTimestamp;
				EDR::Util::SysVersion::GetSysVersion(log->header.Version, sizeof(log->header.Version));

				// body
				log->body.DesiredAccess = DesiredAccess;
				log->body.is_CreateHandleInformation = is_CreateHandleInformation;
				log->body.Target_ProcessId = Target_ProcessId;

				// PID to PATH(CHAR)
				HANDLE Target_ProcessHandle = NULL;
				if (!NT_SUCCESS(EDR::Util::Process::Handle::LookupProcessHandlebyProcessId(Target_ProcessId, &Target_ProcessHandle)))
				{
					ExFreePoolWithTag(log, LogALLOC);
					return FALSE;
				}
				EDR::Util::helper::Process_to_CHAR(Target_ProcessHandle, log->body.TargetProcess_Path, sizeof(log->body.TargetProcess_Path));
				EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(Target_ProcessHandle);


				// 큐
				LogPost::LogPut(log);

				return TRUE;
			}
		}
	}
}