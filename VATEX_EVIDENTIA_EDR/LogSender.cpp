#include "LogSender.hpp"

namespace EDR
{
	namespace LogSender
	{
		BOOLEAN INITIALIZE()
		{
			PAGED_CODE();
			// Consume 스레드생성 (단일)
			HANDLE ConsumeThreadHandle = NULL;
			PsCreateSystemThread(
				&ConsumeThreadHandle,
				THREAD_ALL_ACCESS,
				NULL,
				NULL,
				NULL,
				resource::Consume::Consume,
				NULL
			);
			if (!ConsumeThreadHandle)
				return FALSE;
			else
				resource::is_consume_working = TRUE;
			ZwClose(ConsumeThreadHandle); // Detach

			return TRUE;
		}
		VOID CleanUp()
		{
			resource::Consume::CleanUpNodes();
		}

		namespace resource
		{
			SLIST_HEADER g_ListHead;
			volatile ULONG64 g_NodeCount = 0;  // 노드 개수 카운터

			BOOLEAN is_consume_working = false;

			namespace Produce
			{
				BOOLEAN ProducdeLogData(ULONG64 Type, PVOID UserSpace, SIZE_T UserSpaceSize)
				{

					if (!resource::is_consume_working)
						return FALSE;

					if (g_NodeCount >= MAXIMUM_SLIST_NODE_SIZE)
						return FALSE;


					PLOG_NODE node = (PLOG_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LOG_NODE), LogALLOC);
					if (!node)
						return false;

					node->Type = Type;
					node->UserSpace = UserSpace;
					node->UserSpaceSize = UserSpaceSize;
					InterlockedPushEntrySList(&g_ListHead, &node->Entry); // 노드 추가
					InterlockedIncrement64((volatile LONG64*)&g_NodeCount); // 노드 개수 원자적으로 1씩 증가

					return  TRUE;
				}
			}
			namespace Consume
			{
				void CleanUpNodes()
				{
					if (is_consume_working)
					{
						is_consume_working = FALSE;
						// 남은 노드 엔트리 모두 할당해제
						if (g_NodeCount)
						{
							for (ULONG64 node_count = 0; node_count < g_NodeCount; node_count++)
							{
								PSLIST_ENTRY entry_node = InterlockedPopEntrySList(&g_ListHead);  // 노드 개수 원자적으로 1씩 감소
								if (!entry_node)
									break;

								PLOG_NODE node = CONTAINING_RECORD(entry_node, LOG_NODE, Entry);
								HANDLE APC_Target_ProcessHandle = EDR::IOCTL::IOCTL_PROCESSING::resource::User_AGENT_Process_Handle;

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
				extern "C" VOID Consume(PVOID ctx)
				{
					UNREFERENCED_PARAMETER(ctx);

					const ULONG64 Threshold = 10;
					LARGE_INTEGER interval;

					while (is_consume_working)
					{
						if (g_NodeCount >= Threshold)
						{
							// 현재 큐 사이즈만큼 배치 소비
							ULONG64 consumeCount = g_NodeCount;

							for (ULONG64 i = 0; i < consumeCount; i++)
							{
								PSLIST_ENTRY entry_node = InterlockedPopEntrySList(&g_ListHead);  // 노드 개수 원자적으로 1씩 감소
								if (!entry_node)
									break;

								InterlockedDecrement64((volatile LONG64*)&g_NodeCount);

								PLOG_NODE node = CONTAINING_RECORD(entry_node, LOG_NODE, Entry);

								if (!EDR::APC::ApcToUser(node->Type, node->UserSpace, node->UserSpaceSize))
								{
									HANDLE APC_Target_ProcessHandle = EDR::IOCTL::IOCTL_PROCESSING::resource::User_AGENT_Process_Handle;

									if (APC_Target_ProcessHandle)
									{
										EDR::Util::UserSpace::Memory::FreeMemory(
											APC_Target_ProcessHandle,
											node->UserSpace,
											node->UserSpaceSize
										);
									}
								}

								ExFreePoolWithTag(node, LogALLOC);
							}
							interval.QuadPart = -10 * 100; // 0.0001초
						}
						else
						{
							// 큐가 충분히 쌓이지 않았으면 잠깐 Sleep
							
							interval.QuadPart = -10 * 1000 * 1000; // 1초
							
						}
						KeDelayExecutionThread(KernelMode, FALSE, &interval);
					}
				}
				
			}

		}

		namespace LogPost
		{
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
			}
			namespace SystemThread_method
			{
				extern "C" VOID POST_SystemThread_method(PVOID CTX)
				{
					NTSTATUS status = STATUS_UNSUCCESSFUL;
					EDR::EventLog::Struct::EventLog_Header* logHeader = (EDR::EventLog::Struct::EventLog_Header*)CTX;

					PVOID AllocatedUserSpace = NULL;
					SIZE_T AllocatedUserSpaceSize = 0;
					SIZE_T logSize = 0;

					// APC타겟 유저(USER AGENT 프로세스) PID 유효체크
					HANDLE APC_Target_ProcessHandle = EDR::IOCTL::IOCTL_PROCESSING::resource::User_AGENT_Process_Handle;
					if (!APC_Target_ProcessHandle)
						goto CleanUp;
					HANDLE APC_Target_ProcessId = EDR::IOCTL::IOCTL_PROCESSING::resource::User_AGENT_ProcessId;
					if (!APC_Target_ProcessId)
						goto CleanUp;

					
					switch (logHeader->Type)
					{
						case  EDR::EventLog::Enum::Filesystem:
						{

							
							EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem* log = (EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem*)CTX;
							logSize = sizeof(EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem);

							helper::CHAR_to_FILESIZE(
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
							logSize = sizeof(EDR::EventLog::Struct::Network::EventLog_Process_Network);
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
							EDR::Util::String::Ansi2Unicode::ANSI_to_UnicodeString((PCHAR)log->body.ImagePathAnsi, (ULONG32)( strlen(log->body.ImagePathAnsi) + 1), &ImagePath);

							helper::FilePath_to_HASH(
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
							if (!helper::SID_to_CHAR(log->header.ProcessId, (PCHAR)log->body.post.SID, sizeof(log->body.post.SID)))
								goto CleanUp;

							/*
								Self 프로세스 이미지경로/파일사이즈/해시값 경로구하기
							*/
							helper::Process_to_HASH(
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
							helper::Process_to_HASH(
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

					/*
					// APC 전달
					if (!EDR::APC::ApcToUser((ULONG64)logHeader->Type, AllocatedUserSpace, logSize))
					{
						EDR::Util::UserSpace::Memory::FreeMemory(APC_Target_ProcessHandle, AllocatedUserSpace, AllocatedUserSpaceSize);
					}
					*/
					CleanUp:
					{
						if(CTX)
							ExFreePoolWithTag(CTX, LogALLOC);
					}
				}
			}
		}

		namespace function
		{

			BOOLEAN ProcessCreateLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				HANDLE Parent_ProcessId
			) {
				PAGED_CODE();





				EDR::EventLog::Struct::Process::EventLog_Process_Create* log = (EDR::EventLog::Struct::Process::EventLog_Process_Create*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::EventLog::Struct::Process::EventLog_Process_Create), LogALLOC);
				if (!log)
					return FALSE;
				RtlZeroMemory(log, sizeof(EDR::EventLog::Struct::Process::EventLog_Process_Create));
				log->header.Type = EDR::EventLog::Enum::Process_Create;
				log->header.ProcessId = ProcessId;
				log->header.NanoTimestamp = NanoTimestamp;
				log->body.Parent_ProcessId = Parent_ProcessId;
				EDR::Util::SysVersion::GetSysVersion(log->header.Version, sizeof(log->header.Version));






				HANDLE thread = NULL;
				PsCreateSystemThread(
					&thread,
					THREAD_ALL_ACCESS,
					NULL,
					NULL,
					NULL,
					(PKSTART_ROUTINE)LogPost::SystemThread_method::POST_SystemThread_method,
					log
				);
				if (!thread)
				{
					ExFreePoolWithTag(log, LogALLOC);
					return FALSE;
				}

				ZwClose(thread); // Detach

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


				helper::UNICODE_to_CHAR(
					(PUNICODE_STRING)ImagePath,
					log->body.ImagePathAnsi,
					sizeof(log->body.ImagePathAnsi)
				);






				HANDLE thread = NULL;
				PsCreateSystemThread(
					&thread,
					THREAD_ALL_ACCESS,
					NULL,
					NULL,
					NULL,
					(PKSTART_ROUTINE)LogPost::SystemThread_method::POST_SystemThread_method,
					log
				);
				if (!thread)
				{
					ExFreePoolWithTag(log, LogALLOC);
					return FALSE;
				}

				ZwClose(thread); // Detach

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
				ULONG32 REMOTE_PORT
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


				// WORK_ITEM
				LogPost::WorkItem_method::WORK_CONTEXT* work_context = (LogPost::WorkItem_method::WORK_CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LogPost::WorkItem_method::WORK_CONTEXT), WorkItem_LogALLOC);
				if (!work_context)
				{
					ExFreePoolWithTag(log, LogALLOC);
					return FALSE;
				}


				work_context->LogEvent = log;

				ExInitializeWorkItem(&work_context->Item, LogPost::WorkItem_method::POST_Workitem_method, work_context);
				ExQueueWorkItem(&work_context->Item, NormalWorkQueue);
					
				return TRUE;
			}

			BOOLEAN FilesystemLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				EDR::EventLog::Enum::FileSystem::Filesystem_enum FsEnum,
				UNICODE_STRING* Normalized_FilePath,

				UNICODE_STRING* To_Renmae_FilePath // if NULL< not Rename.
				

			) {
				// ~ APC_LEVEL
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
				helper::UNICODE_to_CHAR(Normalized_FilePath, log->body.FilePath, sizeof(log->body.FilePath));
				//RtlCopyMemory(log->body.SHA256, SHA256, SHA256_STRING_LENGTH); // SHA256

				//if rename
				if (To_Renmae_FilePath)
				{
					log->body.rename.is_valid = TRUE;
					helper::UNICODE_to_CHAR(To_Renmae_FilePath, log->body.rename.RenameFilePath, sizeof(log->body.rename.RenameFilePath));
					
				}
				else
					log->body.rename.is_valid = FALSE;
				

				// WORK_ITEM
				LogPost::WorkItem_method::WORK_CONTEXT* work_context = (LogPost::WorkItem_method::WORK_CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LogPost::WorkItem_method::WORK_CONTEXT), WorkItem_LogALLOC);
				if (!work_context)
				{
					ExFreePoolWithTag(log, LogALLOC);
					return FALSE;
				}


				work_context->LogEvent = log;

				ExInitializeWorkItem(&work_context->Item, LogPost::WorkItem_method::POST_Workitem_method, work_context);
				ExQueueWorkItem(&work_context->Item, NormalWorkQueue);

				return TRUE;
			}

			// Registry
			BOOLEAN Registry_by_CompleteorObjectNameLog(
				EDR::EventLog::Enum::Registry::Registry_enum KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp,
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

				log->body.FunctionName = KeyClass;
				helper::UNICODE_to_CHAR(CompleteName, log->body.Name, sizeof(log->body.Name));

				// WORK_ITEM
				LogPost::WorkItem_method::WORK_CONTEXT* work_context = (LogPost::WorkItem_method::WORK_CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LogPost::WorkItem_method::WORK_CONTEXT), WorkItem_LogALLOC);
				if (!work_context)
				{
					ExFreePoolWithTag(log, LogALLOC);
					return FALSE;
				}


				work_context->LogEvent = log;

				ExInitializeWorkItem(&work_context->Item, LogPost::WorkItem_method::POST_Workitem_method, work_context);
				ExQueueWorkItem(&work_context->Item, NormalWorkQueue);

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
				helper::Process_to_CHAR(Target_ProcessHandle, log->body.TargetProcess_Path, sizeof(log->body.TargetProcess_Path));
				EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(Target_ProcessHandle);





				// WORK_ITEM
				LogPost::WorkItem_method::WORK_CONTEXT* work_context = (LogPost::WorkItem_method::WORK_CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LogPost::WorkItem_method::WORK_CONTEXT), WorkItem_LogALLOC);
				if (!work_context)
				{
					ExFreePoolWithTag(log, LogALLOC);
					return FALSE;
				}


				work_context->LogEvent = log;

				ExInitializeWorkItem(&work_context->Item, LogPost::WorkItem_method::POST_Workitem_method, work_context);
				ExQueueWorkItem(&work_context->Item, NormalWorkQueue);
				return TRUE;
			}

		}
		

		


		namespace helper
		{
			
			BOOLEAN CHAR_to_FILESIZE(PCHAR FIlePathBuffer, ULONG32 FIlePathBufferSize, SIZE_T* FileSize)
			{
				UNICODE_STRING filepath = { 0, };
				if (!EDR::Util::String::Ansi2Unicode::ANSI_to_UnicodeString(FIlePathBuffer, FIlePathBufferSize, &filepath))
					return FALSE;

				if (!EDR::Util::File::Read::Get_FIleSIze(&filepath, FileSize))
				{
					EDR::Util::String::Ansi2Unicode::Release_ANSI_to_UnicodeString(&filepath);
					return FALSE;
				}

				EDR::Util::String::Ansi2Unicode::Release_ANSI_to_UnicodeString(&filepath);
				return TRUE;
			}

			BOOLEAN CHAR_to_HASH(PCHAR FIlePathBuffer, ULONG32 FIlePathBufferSize, PCHAR out_HASHBUFFER, SIZE_T* out_FileSize)
			{
				
				UNICODE_STRING filepath = { 0, };
				if (!EDR::Util::String::Ansi2Unicode::ANSI_to_UnicodeString(FIlePathBuffer, FIlePathBufferSize, &filepath))
					return FALSE;

				// 파일 읽고 해시 구하기
				if (!NT_SUCCESS(EDR::Util::File::Read::ReadFileAndComputeSHA256(
					filepath,
					out_HASHBUFFER,
					out_FileSize)
				))
				{
					EDR::Util::String::Ansi2Unicode::Release_ANSI_to_UnicodeString(&filepath);
					return FALSE;
				}


				EDR::Util::String::Ansi2Unicode::Release_ANSI_to_UnicodeString(&filepath);
				return TRUE;
			}

			BOOLEAN UNICODE_to_CHAR(PUNICODE_STRING input, CHAR* Buffer, SIZE_T BUfferSIze)
			{
				PCHAR ansi = NULL;
				ULONG32 ansi_sz = 0;
				EDR::Util::String::Unicode2Ansi::UnicodeString_to_ANSI(
					input,
					&ansi,
					&ansi_sz
				);
				if (!ansi)
					return FALSE;

				// copy to sendingdata
				RtlCopyMemory(
					Buffer,
					ansi,
					ansi_sz > BUfferSIze ? BUfferSIze : (ansi_sz-1)
				);

				EDR::Util::String::Unicode2Ansi::Release_UnicodeString_to_ANSI(ansi);
				return TRUE;
			}

			BOOLEAN Process_to_HASH(HANDLE ProcessId, CHAR* out_ImagePathNameBuffer, SIZE_T in_ImagePathNameBufferSIze, SIZE_T* out_ImageFileSize, CHAR* out_SHA256Buffer, SIZE_T SHA256BufferSize)
			{
				// 1. 프로세스 핸들 얻기
				HANDLE ProcessHandle = NULL;
				EDR::Util::Process::Handle::LookupProcessHandlebyProcessId(ProcessId, &ProcessHandle);
				if (!ProcessHandle)
					return FALSE;

				// 2. 프로세스 이미지 절대경로 얻기
				PUNICODE_STRING Process_ImagePath = NULL;
				EDR::Util::Process::ImagePath::LookupProcessAbsoluteImagePathbyProcessHandle(ProcessHandle, &Process_ImagePath);
				if (!Process_ImagePath)
				{
					EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(ProcessHandle);
					return FALSE;
				}

				// 3. 프로세스 이미지 해시와 파일크기 얻기
				if (!FilePath_to_HASH(
					Process_ImagePath,
					out_ImageFileSize,
					out_SHA256Buffer,
					SHA256BufferSize
				))
				{
					EDR::Util::Process::ImagePath::ReleaseLookupProcessAbsoluteImagePathbyProcessHandle(Process_ImagePath);
					EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(ProcessHandle);
					return FALSE;
				}

				// Final
				UNICODE_to_CHAR(Process_ImagePath, out_ImagePathNameBuffer, in_ImagePathNameBufferSIze);

				EDR::Util::Process::ImagePath::ReleaseLookupProcessAbsoluteImagePathbyProcessHandle(Process_ImagePath);
				EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(ProcessHandle);
				return TRUE;
			}
			// FilePath to FilePath/FileSize/SHA256
			BOOLEAN FilePath_to_HASH(PUNICODE_STRING UnicodeImagePath, SIZE_T* out_ImageFileSize, CHAR* inout_SHA256Buffer, SIZE_T SHA256BufferSize)
			{
				PUCHAR FileBin = NULL;
				SIZE_T FileBInSz = 0;
				if (!NT_SUCCESS( EDR::Util::File::Read::ReadFile(*UnicodeImagePath, &FileBin, &FileBInSz)) )
					return FALSE;

				PCHAR SHA256 = NULL;
				ULONG SHA256_sz = EDR::Util::Hash::SHA256::SHA256_Hasing(&SHA256, FileBin, FileBInSz);
				if (!SHA256_sz || !SHA256)
				{
					EDR::Util::File::Release_File(FileBin);
					return FALSE;
				}

				RtlCopyMemory(inout_SHA256Buffer, SHA256, SHA256_sz > SHA256BufferSize ? SHA256BufferSize-1 : SHA256_sz);

				*out_ImageFileSize = FileBInSz;

				EDR::Util::Hash::Release_Hashed(SHA256);
				EDR::Util::File::Release_File(FileBin);
				return TRUE;
			}

			BOOLEAN Process_to_CHAR(HANDLE ProcessHandle, CHAR* Buffer, SIZE_T BUfferSIze)
			{
				PUNICODE_STRING EXEImagePath = NULL;
				if (!NT_SUCCESS(EDR::Util::Process::ImagePath::LookupProcessAbsoluteImagePathbyProcessHandle(ProcessHandle, &EXEImagePath)))
					return FALSE;

				if (!UNICODE_to_CHAR(EXEImagePath, Buffer, BUfferSIze))
				{
					EDR::Util::Process::ImagePath::ReleaseLookupProcessAbsoluteImagePathbyProcessHandle(EXEImagePath);
					return FALSE;
				}

				EDR::Util::Process::ImagePath::ReleaseLookupProcessAbsoluteImagePathbyProcessHandle(EXEImagePath);

				return TRUE;
			}

			BOOLEAN SID_to_CHAR(HANDLE ProcessId, CHAR* Buffer, SIZE_T BUfferSIze)
			{
				/*
								SID 추출
							*/
				UNICODE_STRING sid = { 0, };
				NTSTATUS status = EDR::Util::Account::SID::Get_PROCESS_SID(
					ProcessId,
					&sid
				);
				if (!NT_SUCCESS(status))
					return FALSE;

				// Unicode -> Char
				if (!UNICODE_to_CHAR(&sid, Buffer, BUfferSIze))
				{
					EDR::Util::Account::SID::Release_PROCESS_SID(&sid);
					return FALSE;
				}

				EDR::Util::Account::SID::Release_PROCESS_SID(&sid);

				return TRUE;
			}
		}

	}
}