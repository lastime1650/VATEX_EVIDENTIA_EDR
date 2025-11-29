#include "LogSender.hpp"

namespace EDR
{
	namespace LogSender
	{
		ERESOURCE g_Resource;

		PUCHAR CollapseProducedLogs_StartAddress = nullptr;
		PUCHAR CollapseProducedLogs_CurrentAddress = nullptr;
		SIZE_T CollapseProducedLogs_Size = 0;
		FAST_MUTEX CollapseProduceLogs_Mtx;

		BOOLEAN INITIALIZE()
		{
			PAGED_CODE();

			LogPost::is_LogPostWorking = TRUE;

			ExInitializeFastMutex(
				&CollapseProduceLogs_Mtx
			);

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

				BOOLEAN ProduceOnBatch(EDR::LogBuilder::PLOG_BUILDER_CTX context)
				{
					ExAcquireFastMutex(&CollapseProduceLogs_Mtx);

					if (CollapseProducedLogs_StartAddress == nullptr)
					{
						// 처음부터..
						CollapseProducedLogs_StartAddress = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, context->Size, 'Prod'); //context->Buffer;
						RtlCopyMemory(CollapseProducedLogs_StartAddress, context->Buffer, context->Size);
						CollapseProducedLogs_Size = context->Size;

						CollapseProducedLogs_CurrentAddress = CollapseProducedLogs_StartAddress;
					}
					else
					{
						// 이어하기
						// 기존 버퍼 뒤에 새로운 로그 데이터를 이어붙이기
						SIZE_T NewSize = CollapseProducedLogs_Size + context->Size;

						// 새로운 크기의 버퍼 할당
						PUCHAR NewBuffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, NewSize, 'Prod');
						if (!NewBuffer)
						{
							// 할당 실패 시 기존 버퍼 그대로 반환
							ExReleaseFastMutex(&CollapseProduceLogs_Mtx);
							return FALSE;
						}

						// 기존 데이터 복사
						RtlCopyMemory(NewBuffer, CollapseProducedLogs_StartAddress, CollapseProducedLogs_Size);
						// 새 로그 데이터 복사
						RtlCopyMemory(NewBuffer + CollapseProducedLogs_Size, context->Buffer, context->Size);

						// 기존 버퍼 해제
						ExFreePoolWithTag(CollapseProducedLogs_StartAddress, 'Prod');

						// 포인터와 크기 갱신
						CollapseProducedLogs_StartAddress = NewBuffer;
						CollapseProducedLogs_CurrentAddress = CollapseProducedLogs_StartAddress + CollapseProducedLogs_Size;
						CollapseProducedLogs_Size = NewSize;
					}

					ExReleaseFastMutex(&CollapseProduceLogs_Mtx);
					return TRUE;
				}
			}
			namespace Consume
			{
				BOOLEAN ConsumeV2(_In_ HANDLE RequestProcessId, _Out_ PVOID* AllocatedUser, _Out_ ULONG64* Size)
				{
					//debug_break();

					if (!AllocatedUser || !Size)
						return FALSE;

					HANDLE RequesterProcessHandle = NULL;
					if (!NT_SUCCESS(EDR::Util::Process::Handle::LookupProcessHandlebyProcessId(RequestProcessId, &RequesterProcessHandle)))
						return FALSE;

					BOOLEAN ReturnBool = FALSE;

					

					PVOID AllocatedUserSpace = NULL;
					SIZE_T AllocatedUserSpaceSize = CollapseProducedLogs_Size;
					if (!AllocatedUserSpaceSize)
					{
						EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(RequesterProcessHandle);
						return FALSE;
					}
					

					// 유저공간에 할당
					EDR::Util::UserSpace::Memory::AllocateMemory(
						RequesterProcessHandle,
						&AllocatedUserSpace,
						&AllocatedUserSpaceSize
					);
					if (!AllocatedUserSpace)
					{
						EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(RequesterProcessHandle);
						return FALSE;
					}

					ExAcquireFastMutex(&CollapseProduceLogs_Mtx);

					if (!EDR::Util::UserSpace::Memory::Copy(RequestProcessId, AllocatedUserSpace, CollapseProducedLogs_StartAddress, CollapseProducedLogs_Size))
					{
						EDR::Util::UserSpace::Memory::FreeMemory(
							RequesterProcessHandle,
							AllocatedUserSpace,
							AllocatedUserSpaceSize
						);

						*AllocatedUser = NULL;
						*Size = 0;

						goto IS_FAILED;
					}



					*AllocatedUser = AllocatedUserSpace;
					*Size = CollapseProducedLogs_Size;


					goto IS_SUCCESS;
				IS_SUCCESS:
					{
						// 할당해제 [ Collaps ]
						ExFreePoolWithTag(CollapseProducedLogs_StartAddress, 'Prod');
						CollapseProducedLogs_StartAddress = nullptr;
						CollapseProducedLogs_CurrentAddress = nullptr;

						ReturnBool = TRUE;
						goto RETURN;
					}
				IS_FAILED:
					{
						ReturnBool = FALSE;
					}
				RETURN:
					{
						ExReleaseFastMutex(&CollapseProduceLogs_Mtx);
						EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(RequesterProcessHandle);
						return ReturnBool;
					}
					
					
				}
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

						BOOLEAN IS_SUCCESS = FALSE;

						auto* Context = (EDR::LogBuilder::PLOG_BUILDER_CTX)CTX;

						switch (Context->LogType)
						{
						case EDR::EventLog::Enum::Process_Create:
						{
							{
								// Processid 가져오기
								PUCHAR ProcessId_ptr = nullptr;
								PUCHAR Parent_ProcessId_ptr = nullptr;
								SIZE_T Got_SIze;
								

								if (!EDR::LogBuilder::helper::GetDataByIndex(	// 자신 Processid 가져오기
									Context,
									0,
									&ProcessId_ptr,
									&Got_SIze
								))
									goto CleanUp;

								if (!EDR::LogBuilder::helper::GetDataByIndex(	// ParentProcessId가져오기
									Context,
									2,
									&Parent_ProcessId_ptr,
									&Got_SIze
								))
									goto CleanUp;

								
								*(HANDLE*)ProcessId_ptr;
								*(HANDLE*)Parent_ProcessId_ptr;

								{
									// File Hashing
									PWCH ImagePathNameBuffer = nullptr;
									ULONG32 ImagePathNameBufferMaxLen = 0;
									SIZE_T ImageSize = 0;
									PCHAR ImageSha256Buffer = nullptr;
									ULONG32 ImageSha256Size = 0;

									PWCH Parent_ImagePathNameBuffer = nullptr;
									ULONG32 Parent_ImagePathNameBufferMaxLen = 0;
									SIZE_T Parent_ImageSize = 0;
									PCHAR Parent_ImageSha256Buffer = nullptr;
									ULONG32 Parent_ImageSha256Size = 0;


									if( !EDR::Util::helper::Process_to_HASH(
										*(HANDLE*)ProcessId_ptr,
										&ImagePathNameBuffer,
										&ImagePathNameBufferMaxLen,
										&ImageSize,
										&ImageSha256Buffer,
										&ImageSha256Size
									) )
										goto CleanUp;

									if (!EDR::Util::helper::Process_to_HASH(
										*(HANDLE*)Parent_ProcessId_ptr,
										&Parent_ImagePathNameBuffer,
										&Parent_ImagePathNameBufferMaxLen,
										&Parent_ImageSize,
										&Parent_ImageSha256Buffer,
										&Parent_ImageSha256Size
									))
										goto CleanUp;

									PWCH SID_Buff;
									SIZE_T SID_Buff_Size;
									if (!EDR::Util::helper::Get_SID(*(HANDLE*)ProcessId_ptr, &SID_Buff, &SID_Buff_Size))
										goto CleanUp;

									{
										// Append
										// SID
										EDR::LogBuilder::LogBuilder_Append(
											Context,
											(PUCHAR)SID_Buff,
											SID_Buff_Size
										);
										
										
										// 1) 경로 , 2) 사이즈 , 3) 해시

										// 자신 프로세스
										EDR::LogBuilder::LogBuilder_Append(
											Context,
											(PUCHAR)ImagePathNameBuffer,
											ImagePathNameBufferMaxLen
										);
										EDR::LogBuilder::LogBuilder_Append(
											Context,
											(PUCHAR)&ImageSize,
											sizeof(ImageSize)
										);
										EDR::LogBuilder::LogBuilder_Append(
											Context,
											(PUCHAR)ImageSha256Buffer,
											ImageSha256Size
										);

										// 부모 프로세스
										EDR::LogBuilder::LogBuilder_Append(
											Context,
											(PUCHAR)Parent_ImagePathNameBuffer,
											Parent_ImagePathNameBufferMaxLen
										);
										EDR::LogBuilder::LogBuilder_Append(
											Context,
											(PUCHAR)&Parent_ImageSize,
											sizeof(Parent_ImageSize)
										);
										EDR::LogBuilder::LogBuilder_Append(
											Context,
											(PUCHAR)Parent_ImageSha256Buffer,
											Parent_ImageSha256Size
										);
									}


									EDR::Util::helper::Release_SID(SID_Buff);
									EDR::Util::helper::Process_to_HASH_Release(ImagePathNameBuffer, ImageSha256Buffer);
									EDR::Util::helper::Process_to_HASH_Release(Parent_ImagePathNameBuffer, Parent_ImageSha256Buffer);

									IS_SUCCESS = TRUE;
								}

							}
							break;
						}
						
						case EDR::EventLog::Enum::ImageLoad:
						{
							PWCH ImagePathBuffer;
							SIZE_T ImagePathBufferMaxLen;

							if (!EDR::LogBuilder::helper::GetDataByIndex(	// Loaded Image PWCH 가져오기
								Context,
								2,
								((PUCHAR*)&ImagePathBuffer ),
								&ImagePathBufferMaxLen
							))
								goto CleanUp;

							UNICODE_STRING ImagePath;
							RtlInitUnicodeString(&ImagePath, ImagePathBuffer);
							ULONG64 ImageSize = 0;

							CHAR TempSha256[65];
							EDR::Util::helper::FilePath_to_HASH(
								&ImagePath,
								&ImageSize,
								TempSha256,
								65
							);

							//debug_log("ImagePath: %wZ / ImageSIze: %llu / SHA: %s \n", ImagePath, ImageSize, TempSha256);

							{
								// append
								EDR::LogBuilder::LogBuilder_Append(
									Context,
									(PUCHAR)&ImageSize,
									sizeof(ImageSize)
								);
								EDR::LogBuilder::LogBuilder_Append(
									Context,
									(PUCHAR)TempSha256,
									sizeof(TempSha256)
								);
							}

							IS_SUCCESS = TRUE;
							break;
						}
						case EDR::EventLog::Enum::Filesystem:
						{
							PWCH FilePathBuffer;
							SIZE_T FilePathBufferMaxLen;

							if (!EDR::LogBuilder::helper::GetDataByIndex(	// Loaded Image PWCH 가져오기
								Context,
								3,
								((PUCHAR*)&FilePathBuffer),
								&FilePathBufferMaxLen
							))
								goto CleanUp;

							UNICODE_STRING FilePath;
							RtlInitUnicodeString(&FilePath, FilePathBuffer);
							ULONG64 FileSize = 0;

							EDR::Util::File::Read::Get_FIleSIze(
								&FilePath,
								&FileSize
							);


							{
								// Append
								EDR::LogBuilder::LogBuilder_Append(
									Context,
									(PUCHAR)&FileSize,
									sizeof(FileSize)
								);
							}
							IS_SUCCESS = TRUE;
							break;
						}

						case EDR::EventLog::Enum::Network:
						case EDR::EventLog::Enum::ObRegisterCallback:
						case EDR::EventLog::Enum::Registry_OldNewLog:
						case EDR::EventLog::Enum::Registry_CompleteNameLog:
						case EDR::EventLog::Enum::Process_Terminate:
						{
							IS_SUCCESS = TRUE;
							break;
						}
						default:
							break;
						}

						if (!IS_SUCCESS)
							goto CleanUp;


						// Closing
						EDR::LogBuilder::LogBuilder_Closing(
							Context
						);

						// Produce
						EDR::LogSender::resource::Produce::ProduceOnBatch(Context);

					CleanUp:
						{
							EDR::LogBuilder::LogBuilder_Remove(Context);
							EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
							Context = NULL;
						}

							/*
							NTSTATUS status = STATUS_UNSUCCESSFUL;
							EDR::EventLog::Struct::EventLog_Header* logHeader = (EDR::EventLog::Struct::EventLog_Header*)CTX;

							PVOID AllocatedUserSpace = NULL;
							SIZE_T AllocatedUserSpaceSize = 0;
							SIZE_T logSize = 0;

							// APC타겟 유저(USER AGENT 프로세스) PID 유효체크

							HANDLE UserAGENT_ProcessHandle = EDR::Util::Shared::USER_AGENT::ProcessHandle;
							if (!UserAGENT_ProcessHandle)
								goto CleanUp;
							HANDLE UserAGENT_ProcessId = EDR::Util::Shared::USER_AGENT::ProcessId;
							if (!UserAGENT_ProcessId)
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
									UserAGENT_ProcessHandle,
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
									UserAGENT_ProcessHandle,
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
									UserAGENT_ProcessHandle,
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


									SID 추출

								if (!EDR::Util::helper::SID_to_CHAR(log->header.ProcessId, (PCHAR)log->body.post.SID, sizeof(log->body.post.SID)))
									goto CleanUp;


									lf 프로세스 이미지경로/파일사이즈/해시값 경로구하기

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


									Parent 프로세스 이미지경로/파일사이즈/해시값 경로구하기

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


									Parent 프로세스 실행파일(1) 및 SHA256(2) 구하기


								AllocatedUserSpaceSize = logSize;
								// User 공간 Allocate
								EDR::Util::UserSpace::Memory::AllocateMemory(
									UserAGENT_ProcessHandle,
									&AllocatedUserSpace,
									&AllocatedUserSpaceSize
								);

								if (!AllocatedUserSpace)
									goto CleanUp;

								break;
							}
							case EDR::EventLog::Enum::Registry_CompleteNameLog:
							{
								EDR::EventLog::Struct::Registry::EventLog_Process_Registry_CompleteorObjectNameLog* log = (EDR::EventLog::Struct::Registry::EventLog_Process_Registry_CompleteorObjectNameLog*)CTX;
								logSize = sizeof(EDR::EventLog::Struct::Registry::EventLog_Process_Registry_CompleteorObjectNameLog);

								// 1. Name(wcs) -> Char
								UNICODE_STRING NAME_UNICODE;
								RtlInitUnicodeString(&NAME_UNICODE, log->body.post.Name);
								if (!EDR::Util::helper::UNICODE_to_CHAR(&NAME_UNICODE, log->body.Name, sizeof(log->body.Name)))
								{
									ExFreePoolWithTag(log->body.post.Name, LogALLOC); // PWCH 동적할당 해제
									goto CleanUp;
								}


								ExFreePoolWithTag(log->body.post.Name, LogALLOC); // PWCH 동적할당 해제

								AllocatedUserSpaceSize = logSize;
								// User 공간 Allocate
								EDR::Util::UserSpace::Memory::AllocateMemory(
									UserAGENT_ProcessHandle,
									&AllocatedUserSpace,
									&AllocatedUserSpaceSize
								);

								if (!AllocatedUserSpace)
									goto CleanUp;

								break;
							}
							case EDR::EventLog::Enum::Registry_OldNewLog:
							{
								EDR::EventLog::Struct::Registry::EventLog_Process_Registry_OldNewNameLog* log = (EDR::EventLog::Struct::Registry::EventLog_Process_Registry_OldNewNameLog*)CTX;
								logSize = sizeof(EDR::EventLog::Struct::Registry::EventLog_Process_Registry_OldNewNameLog);

								// 1. Name 처리
								UNICODE_STRING NAME_UNICODE;
								RtlInitUnicodeString(&NAME_UNICODE, log->body.post.Name);
								if (!EDR::Util::helper::UNICODE_to_CHAR(&NAME_UNICODE, log->body.Name, sizeof(log->body.Name)))
								{
									// 실패 시: Name 해제 및 나머지(Old, New)도 해제 필요
									ExFreePoolWithTag(log->body.post.Name, LogALLOC);
									if (log->body.post.OldName) ExFreePoolWithTag(log->body.post.OldName, LogALLOC);
									if (log->body.post.NewName) ExFreePoolWithTag(log->body.post.NewName, LogALLOC);
									goto CleanUp;
								}
								ExFreePoolWithTag(log->body.post.Name, LogALLOC);
								log->body.post.Name = NULL; // 해제 후 NULL 처리 권장

								// 2. OldName 처리
								UNICODE_STRING OldNAME_UNICODE;
								RtlInitUnicodeString(&OldNAME_UNICODE, log->body.post.OldName);
								if (!EDR::Util::helper::UNICODE_to_CHAR(&OldNAME_UNICODE, log->body.OldName, sizeof(log->body.OldName)))
								{
									// 실패 시: OldName 해제 및 나머지(New)도 해제 필요 (Name은 위에서 이미 해제됨)
									ExFreePoolWithTag(log->body.post.OldName, LogALLOC);
									if (log->body.post.NewName) ExFreePoolWithTag(log->body.post.NewName, LogALLOC);
									goto CleanUp;
								}
								ExFreePoolWithTag(log->body.post.OldName, LogALLOC);
								log->body.post.OldName = NULL;

								// 3. NewName 처리
								UNICODE_STRING NewNAME_UNICODE;
								RtlInitUnicodeString(&NewNAME_UNICODE, log->body.post.NewName);
								if (!EDR::Util::helper::UNICODE_to_CHAR(&NewNAME_UNICODE, log->body.NewName, sizeof(log->body.NewName)))
								{
									ExFreePoolWithTag(log->body.post.NewName, LogALLOC);
									goto CleanUp;
								}
								ExFreePoolWithTag(log->body.post.NewName, LogALLOC);



								AllocatedUserSpaceSize = logSize;
								// User 공간 Allocate
								EDR::Util::UserSpace::Memory::AllocateMemory(
									UserAGENT_ProcessHandle,
									&AllocatedUserSpace,
									&AllocatedUserSpaceSize
								);

								if (!AllocatedUserSpace)
									goto CleanUp;

								break;
							}
							case EDR::EventLog::Enum::apicall:
							{
								EDR::EventLog::Struct::ApiCall::EventLog_ApiCall* log = (EDR::EventLog::Struct::ApiCall::EventLog_ApiCall*)CTX;
								logSize = sizeof(EDR::EventLog::Struct::ApiCall::EventLog_ApiCall);

								AllocatedUserSpaceSize = logSize;
								// User 공간 Allocate
								EDR::Util::UserSpace::Memory::AllocateMemory(
									UserAGENT_ProcessHandle,
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
							EDR::Util::UserSpace::Memory::Copy(UserAGENT_ProcessId, AllocatedUserSpace, CTX, logSize);


							// Producing Log
							EDR::LogSender::resource::Produce::ProducdeLogData((ULONG64)logHeader->Type, AllocatedUserSpace, logSize);

						CleanUp:
							{
								if (CTX)
									ExFreePoolWithTag(CTX, LogALLOC);
							}
						}*/
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

				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::Process_Create, ProcessId, NanoTimestamp);
				if (!Context)
					return FALSE;

				// Parameters
				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR) & Parent_ProcessId,
					sizeof(Parent_ProcessId)
				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)CommandLine->Buffer,
					CommandLine->MaximumLength
				);

				if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				return TRUE;
				
			}

			BOOLEAN ProcessTerminateLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp
			) {
				PAGED_CODE();

				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::Process_Terminate, ProcessId, NanoTimestamp);
				if (!Context)
					return FALSE;

				// Parameters
				// X

				if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				return TRUE;
			}

			BOOLEAN ImageLoadLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				PCUNICODE_STRING ImagePath
			) {

				PAGED_CODE();

				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::ImageLoad, ProcessId, NanoTimestamp);
				if (!Context)
					return FALSE;

				// Parameters
				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)ImagePath->Buffer,
					ImagePath->MaximumLength
				);

				if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				return TRUE;
			}

			BOOLEAN NetworkLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				PUCHAR SourceMacAddress,
				PUCHAR DestinationMacAddress,

				ULONG32 ProtocolNumber,
				BOOLEAN is_INBOUND,
				ULONG32 PacketSize,

				PUCHAR LOCAL_IP,
				ULONG32 LOCAL_IP_StrSIze,
				ULONG32 LOCAL_PORT,

				PUCHAR REMOTE_IP,
				ULONG32 REMOTE_IP_StrSIze,
				ULONG32 REMOTE_PORT,

				ULONG32 NetworkInterfaceIndex,

				PUCHAR PacketFrameBuffer
			)
			{

				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::Network, ProcessId, NanoTimestamp);
				if (!Context)
					return FALSE;

				// 각 필드 하나하나 append
				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)&ProtocolNumber,
					sizeof(ProtocolNumber)
				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)&is_INBOUND,
					sizeof(is_INBOUND)
				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)&PacketSize,
					sizeof(PacketSize)
				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)&NetworkInterfaceIndex,
					sizeof(NetworkInterfaceIndex)
				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					SourceMacAddress,
					18
				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					DestinationMacAddress,
					18
				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					LOCAL_IP,
					LOCAL_IP_StrSIze+1
				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)&LOCAL_PORT,
					sizeof(LOCAL_PORT)
				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					REMOTE_IP,
					REMOTE_IP_StrSIze + 1
				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)&REMOTE_PORT,
					sizeof(REMOTE_PORT)
				);

				// 패킷 전체 append
				EDR::LogBuilder::LogBuilder_Append(
					Context,
					PacketFrameBuffer,
					PacketSize
				);

				if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				return TRUE;

				/*

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
					log->body.SourceMacAddress,
					SourceMacAddress,
					17
				);
				log->body.LOCAL_PORT = LOCAL_PORT;

				RtlCopyMemory(
					log->body.DestinationMacAddress,
					DestinationMacAddress,
					17
				);
				log->body.REMOTE_PORT = REMOTE_PORT;

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

				// 패킷 전체 ( 점보 포함 )
				RtlCopyMemory(
					log->body.PacketBuffer,
					PacketFrameBuffer,
					PacketSize
				);

				// 큐
				if (!LogPost::LogPut(log))
				{
					ExFreePoolWithTag(log, LogALLOC);
					return FALSE;
				}
					

				return TRUE;*/
			}

			BOOLEAN FilesystemLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				EDR::EventLog::Enum::FileSystem::Filesystem_enum FsEnum,
				UNICODE_STRING* Normalized_FilePath,

				UNICODE_STRING* To_Renmae_FilePath, // if NULL< not Rename.
				PCHAR SHA256

			) {

				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::Filesystem, ProcessId, NanoTimestamp);
				if (!Context)
					return FALSE;

				// Parameters
				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)&FsEnum,
					sizeof(FsEnum)

				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)Normalized_FilePath->Buffer,
					Normalized_FilePath->MaximumLength
				);

				if (To_Renmae_FilePath)
				{
					EDR::LogBuilder::LogBuilder_Append(
						Context,
						(PUCHAR)To_Renmae_FilePath->Buffer,
						To_Renmae_FilePath->MaximumLength
					);
				}
				else
					EDR::LogBuilder::LogBuilder_Append(
						Context,
						(PUCHAR)L"none",
						sizeof(L"none")
					);
				

				if (SHA256)
				{
					EDR::LogBuilder::LogBuilder_Append(
						Context,
						(PUCHAR)SHA256,
						SHA256_String_Byte_Length
					);
				}
				else
					EDR::LogBuilder::LogBuilder_Append(
						Context,
						(PUCHAR)"none",
						sizeof("none")
					);


				if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				return TRUE;
			}

			// Registry
			BOOLEAN Registry_by_CompleteorObjectNameLog(
				PCHAR KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp,
				PUNICODE_STRING CompleteName
			)
			{

				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::Registry_CompleteNameLog, ProcessId, NanoTimestamp);
				if (!Context)
					return FALSE;

				// Parameters

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)KeyClass,
					(ULONG32)strlen(KeyClass)+1

				);

				/*
					[특이사항]
						CmRegistryCallbacks에서 얻은 { CompleteName의 Maximum 값은 널이상의 바이트 수가 책정될 수 있음. }
				*/
				USHORT validDataSize = CompleteName->Length;
				ULONG totalSizeWithNull = validDataSize + sizeof(WCHAR);
				PVOID tempBuffer = ExAllocatePoolWithTag(NonPagedPool, totalSizeWithNull, 'Tag1');
				if (tempBuffer) {
					// 4. 메모리 0으로 초기화 (이러면 맨 끝은 자동으로 NULL이 됨)
					RtlZeroMemory(tempBuffer, totalSizeWithNull);

					// 5. 실제 문자열 데이터 복사 (NULL 자리 직전까지만)
					RtlCopyMemory(tempBuffer, CompleteName->Buffer, validDataSize);

					// 6. LogBuilder에 '널이 포함된 완성된 버퍼'를 전달
					EDR::LogBuilder::LogBuilder_Append(
						Context,
						(PUCHAR)tempBuffer,
						totalSizeWithNull // 실제 데이터 길이 + 널(2바이트)
					);

					// 7. 임시 버퍼 해제
					ExFreePoolWithTag(tempBuffer, 'Tag1');
				}

				if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				return TRUE;
			}

			BOOLEAN Registry_by_OldNewNameLog(
				PCHAR KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp,
				PUNICODE_STRING Name, PUNICODE_STRING Old, PUNICODE_STRING New
			)
			{
				if (Name == NULL || Name->Buffer == NULL) {
					return FALSE;
				}

				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::Registry_OldNewLog, ProcessId, NanoTimestamp);
				if (!Context)
					return FALSE;

				// Parameters

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)KeyClass,
					(ULONG32)strlen(KeyClass)+1

				);

				if (Name)
				{
					EDR::LogBuilder::LogBuilder_Append(
						Context,
						(PUCHAR)Name->Buffer,
						Name->MaximumLength
					);
				}
				else
					EDR::LogBuilder::LogBuilder_Append(
						Context,
						(PUCHAR)L"none",
						sizeof(L"none")
					);
				
				if (Old)
				{
					EDR::LogBuilder::LogBuilder_Append(
						Context,
						(PUCHAR)Old->Buffer,
						Old->MaximumLength
					);
				}
				else
					EDR::LogBuilder::LogBuilder_Append(
						Context,
						(PUCHAR)L"none",
						sizeof(L"none")
					);

				if (New)
				{
					EDR::LogBuilder::LogBuilder_Append(
						Context,
						(PUCHAR)New->Buffer,
						New->MaximumLength
					);
				}
				else
					EDR::LogBuilder::LogBuilder_Append(
						Context,
						(PUCHAR)L"none",
						sizeof(L"none")
					);



				if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

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

				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::ObRegisterCallback, ProcessId, NanoTimestamp);
				if (!Context)
					return FALSE;

				// Parameters

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)&DesiredAccess,
					sizeof(DesiredAccess)
				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)&is_CreateHandleInformation,
					sizeof(is_CreateHandleInformation)
				);

				EDR::LogBuilder::LogBuilder_Append(
					Context,
					(PUCHAR)&Target_ProcessId,
					sizeof(Target_ProcessId)
				);



				if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				return TRUE;

				/*
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
				if (!LogPost::LogPut(log))
				{
					ExFreePoolWithTag(log, LogALLOC);
					return FALSE;
				}

				return TRUE;*/
			}

			// api call
			BOOLEAN API_CallLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				PCHAR JsonStr,
				ULONG32 JsonStrStrLen
			)
			{
				if (!JsonStr || !ProcessId || !NanoTimestamp)
					return FALSE;

				EDR::EventLog::Struct::ApiCall::EventLog_ApiCall* log = (EDR::EventLog::Struct::ApiCall::EventLog_ApiCall*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::EventLog::Struct::ApiCall::EventLog_ApiCall), LogALLOC);
				if (!log)
					return FALSE;
				RtlZeroMemory(log, sizeof(EDR::EventLog::Struct::ApiCall::EventLog_ApiCall) );
				log->header.Type = EDR::EventLog::Enum::apicall;
				log->header.ProcessId = ProcessId;
				log->header.NanoTimestamp = NanoTimestamp;
				EDR::Util::SysVersion::GetSysVersion(log->header.Version, sizeof(log->header.Version));

				// body
				memcpy(log->body.Json, JsonStr, JsonStrStrLen+1 > (8192) ? 8192 : JsonStrStrLen);

				// 큐
				if (!LogPost::LogPut(log))
				{
					ExFreePoolWithTag(log, LogALLOC);
					return FALSE;
				}

				return TRUE;
			}

		}
	}
}