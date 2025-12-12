
#include "LogSender.hpp"

namespace EDR
{
	namespace LogSender
	{
		// -----------------------------------------------------------------------------
		// [ 전역 변수 ] 5개의 독립 파이프라인 인스턴스
		// -----------------------------------------------------------------------------
		LOG_PIPELINE_CTX g_Pipelines[resource::MaxCount];

		// SLIST 최대 깊이 제한
#define MAXIMUM_SLIST_NODE_SIZE 65535

		BOOLEAN INITIALIZE()
		{
			PAGED_CODE();

			LogPost::is_LogPostWorking = TRUE;

			// -------------------------------------------------------------------------
			// 5개의 파이프라인을 루프를 돌며 초기화
			// -------------------------------------------------------------------------
			for (int i = 0; i < resource::MaxCount; i++)
			{
				PLOG_PIPELINE_CTX pPipeline = &g_Pipelines[i];

				// 1. 멤버 초기화
				pPipeline->Type = (resource::QueueTypes)i;
				pPipeline->BatchBuffer = nullptr;
				pPipeline->BatchSize = 0;
				pPipeline->ThreadHandle = NULL;

				// 2. 동기화 객체 초기화
				// 입력 큐 (NonPaged)
				ExInitializeSListHead(&pPipeline->ListHead);
				// 출력 버퍼 보호용 Mutex
				ExInitializeFastMutex(&pPipeline->BatchMtx);

				// 3. 전담 워커 스레드 생성
				// Context로 파이프라인 객체 포인터를 직접 전달
				HANDLE THREAD = NULL;
				NTSTATUS status = PsCreateSystemThread(
					&THREAD,
					THREAD_ALL_ACCESS,
					NULL,
					NULL,
					NULL,
					(PKSTART_ROUTINE)EDR::LogSender::LogPost::SystemThread_method::POST_SystemThread_method,
					(PVOID)pPipeline
				);

				if (NT_SUCCESS(status) && THREAD)
				{
					// 스레드 핸들 저장 (필요시 사용, 여기선 일단 닫음)
					pPipeline->ThreadHandle = THREAD;
					ZwClose(THREAD); // 커널 핸들 테이블에서 제거 (스레드는 계속 실행됨)
				}
			}

			return TRUE;
		}

		VOID CleanUp()
		{
			// 1. 작업 플래그 해제 (스레드 종료 유도)
			LogPost::is_LogPostWorking = FALSE;

			// 2. 잠시 대기 (스레드가 루프를 빠져나올 시간 부여) - 선택사항
			LARGE_INTEGER interval;
			interval.QuadPart = -2000000LL; // 200ms
			KeDelayExecutionThread(KernelMode, FALSE, &interval);

			// 3. 잔여 노드 정리
			LogPost::CleanUpLogNodes();

			// 4. 배치 버퍼 해제
			for (int i = 0; i < resource::MaxCount; i++)
			{
				PLOG_PIPELINE_CTX pPipeline = &g_Pipelines[i];

				ExAcquireFastMutex(&pPipeline->BatchMtx);
				if (pPipeline->BatchBuffer)
				{
					ExFreePoolWithTag(pPipeline->BatchBuffer, Prod_ALLOC);
					pPipeline->BatchBuffer = nullptr;
					pPipeline->BatchSize = 0;
				}
				ExReleaseFastMutex(&pPipeline->BatchMtx);
			}
		}

		namespace resource
		{
			namespace Produce
			{
				BOOLEAN ProduceOnBatch(PLOG_PIPELINE_CTX pPipeline, EDR::LogBuilder::PLOG_BUILDER_CTX context)
				{
					// [중요] 해당 파이프라인의 락만 획득 (완전 병렬성 보장)
					ExAcquireFastMutex(&pPipeline->BatchMtx);

					if (pPipeline->BatchBuffer == nullptr)
					{
						// 처음 할당
						pPipeline->BatchBuffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, context->Size, Prod_ALLOC);
						if (pPipeline->BatchBuffer)
						{
							RtlCopyMemory(pPipeline->BatchBuffer, context->Buffer, context->Size);
							pPipeline->BatchSize = context->Size;
						}
					}
					else
					{
						// 이어 붙이기 (Reallocation)
						SIZE_T NewSize = pPipeline->BatchSize + context->Size;
						PUCHAR NewBuffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, NewSize, Prod_ALLOC);

						if (NewBuffer)
						{
							// 기존 데이터 복사
							RtlCopyMemory(NewBuffer, pPipeline->BatchBuffer, pPipeline->BatchSize);
							// 새 데이터 복사
							RtlCopyMemory(NewBuffer + pPipeline->BatchSize, context->Buffer, context->Size);

							// 구 버퍼 해제
							ExFreePoolWithTag(pPipeline->BatchBuffer, Prod_ALLOC);

							// 포인터 교체
							pPipeline->BatchBuffer = NewBuffer;
							pPipeline->BatchSize = NewSize;
						}
						// 할당 실패 시 기존 버퍼 유지 (이번 로그는 드랍)
					}

					ExReleaseFastMutex(&pPipeline->BatchMtx);
					return TRUE;
				}
			}

			namespace Consume
			{
				// 유저 모드 요청 처리 (IOCTL 핸들러에서 호출)
				BOOLEAN ConsumeV2(resource::QueueTypes Type, _In_ HANDLE RequestProcessId, _Out_ PVOID* AllocatedUser, _Out_ ULONG64* Size)
				{
					if (Type >= resource::MaxCount || !AllocatedUser || !Size)
						return FALSE;

					*AllocatedUser = NULL;
					*Size = 0;

					// 요청된 파이프라인 선택
					PLOG_PIPELINE_CTX pPipeline = &g_Pipelines[Type];

					HANDLE RequesterProcessHandle = NULL;
					if (!NT_SUCCESS(EDR::Util::Process::Handle::LookupProcessHandlebyProcessId(RequestProcessId, &RequesterProcessHandle)))
						return FALSE;

					BOOLEAN ReturnBool = FALSE;

					// [중요] 해당 파이프라인 락 획득
					ExAcquireFastMutex(&pPipeline->BatchMtx);

					if (pPipeline->BatchSize == 0 || pPipeline->BatchBuffer == nullptr)
					{
						ExReleaseFastMutex(&pPipeline->BatchMtx);
						EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(RequesterProcessHandle);
						return FALSE;
					}

					// 유저 공간 할당 준비
					PVOID UserSpaceMem = NULL;
					SIZE_T UserSpaceSize = pPipeline->BatchSize;

					// 유저 프로세스 메모리 할당 (Util 함수 사용)
					EDR::Util::UserSpace::Memory::AllocateMemory(
						RequesterProcessHandle,
						&UserSpaceMem,
						&UserSpaceSize
					);

					if (!UserSpaceMem)
					{
						ExReleaseFastMutex(&pPipeline->BatchMtx);
						EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(RequesterProcessHandle);
						return FALSE;
					}

					// 데이터 복사 (Kernel -> User)
					if (EDR::Util::UserSpace::Memory::Copy(RequestProcessId, UserSpaceMem, pPipeline->BatchBuffer, pPipeline->BatchSize))
					{
						*AllocatedUser = UserSpaceMem;
						*Size = pPipeline->BatchSize;

						// [성공] 커널 버퍼 비우기
						ExFreePoolWithTag(pPipeline->BatchBuffer, Prod_ALLOC);
						pPipeline->BatchBuffer = nullptr;
						pPipeline->BatchSize = 0;

						ReturnBool = TRUE;
					}
					else
					{
						// 복사 실패 시 유저 메모리 해제
						EDR::Util::UserSpace::Memory::FreeMemory(RequesterProcessHandle, UserSpaceMem, UserSpaceSize);
						ReturnBool = FALSE;
					}

					ExReleaseFastMutex(&pPipeline->BatchMtx);
					EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(RequesterProcessHandle);

					return ReturnBool;
				}
			}
		}

		namespace LogPost
		{
			BOOLEAN is_LogPostWorking = FALSE;

			// -------------------------------------------------------------------------
			// Producer: 로그를 특정 파이프라인 큐에 넣음
			// -------------------------------------------------------------------------
			BOOLEAN LogPut(resource::QueueTypes Type, PVOID log)
			{
				if (Type >= resource::MaxCount) return FALSE;

				PLOG_PIPELINE_CTX pPipeline = &g_Pipelines[Type];

				// SLIST 깊이 제한 체크
				USHORT NodeCount = QueryDepthSList(&pPipeline->ListHead);
				if (NodeCount >= MAXIMUM_SLIST_NODE_SIZE)
					return FALSE; // Drop

				PLOG_QUEUE_NODE node = (PLOG_QUEUE_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LOG_QUEUE_NODE), Log_SLIST_ALLOC);
				if (!node) return FALSE;

				node->log = log;

				// 해당 파이프라인 큐에 푸시
				InterlockedPushEntrySList(&pPipeline->ListHead, &node->Entry);
				return TRUE;
			}

			// -------------------------------------------------------------------------
			// Internal Consumer: 파이프라인 큐에서 꺼냄
			// -------------------------------------------------------------------------
			BOOLEAN LogGet(PLOG_PIPELINE_CTX pPipeline, _Out_ PVOID* log)
			{
				*log = NULL;
				PSLIST_ENTRY Entry = InterlockedPopEntrySList(&pPipeline->ListHead);
				if (!Entry) return FALSE;

				PLOG_QUEUE_NODE node = CONTAINING_RECORD(Entry, LOG_QUEUE_NODE, Entry);
				if (node)
				{
					*log = node->log;
					ExFreePoolWithTag(node, Log_SLIST_ALLOC);
					return TRUE;
				}
				return FALSE;
			}

			// 정리 함수
			VOID CleanUpLogNodes()
			{
				// 모든 파이프라인을 순회하며 잔여 노드 제거
				for (int i = 0; i < resource::MaxCount; i++)
				{
					PLOG_PIPELINE_CTX pPipeline = &g_Pipelines[i];

					// SLIST 비우기
					PSLIST_ENTRY Entry;
					while ((Entry = InterlockedPopEntrySList(&pPipeline->ListHead)) != NULL)
					{
						PLOG_QUEUE_NODE node = CONTAINING_RECORD(Entry, LOG_QUEUE_NODE, Entry);

						// Context 내부 메모리도 해제해야 한다면 여기서 수행 (LogBuilder_Remove 등)
						// 여기서는 노드 자체와 Context 메모리만 해제 가정
						if (node->log) {
							// EDR::LogBuilder::LogBuilder_Remove((EDR::LogBuilder::PLOG_BUILDER_CTX)node->log); // 필요시
							EDR::LogBuilder::Terminate_LOG_BUILDER_CTX((EDR::LogBuilder::PLOG_BUILDER_CTX)node->log);
						}

						ExFreePoolWithTag(node, Log_SLIST_ALLOC);
					}
				}
			}

			namespace SystemThread_method
			{
				// ---------------------------------------------------------------------
				// [ 워커 스레드 ]
				// 각 스레드는 하나의 파이프라인(pPipeline)을 전담하여 처리함
				// ---------------------------------------------------------------------
				extern "C" VOID POST_SystemThread_method(PVOID Context)
				{
					PLOG_PIPELINE_CTX pPipeline = (PLOG_PIPELINE_CTX)Context;

					// 스레드 루프
					while (is_LogPostWorking)
					{
						PVOID RawCtx = NULL;

						// 1. 내 담당 큐에서 로그 가져오기
						if (!LogGet(pPipeline, &RawCtx))
						{
							// 큐가 비었으면 Sleep (10ms)
							LARGE_INTEGER interval;
							interval.QuadPart = -100000LL; // 100ns 단위 * 100000 = 10ms
							KeDelayExecutionThread(KernelMode, FALSE, &interval);
							continue;
						}

						auto* BuilderContext = (EDR::LogBuilder::PLOG_BUILDER_CTX)RawCtx;

						BOOLEAN IS_SUCCESS = FALSE;

						switch (BuilderContext->LogType)
						{
						case EDR::EventLog::Enum::Process_Create:
						{
							{
								// Processid 가져오기
								PUCHAR ProcessId_ptr = nullptr;
								PUCHAR Parent_ProcessId_ptr = nullptr;
								SIZE_T Got_SIze;


								if (!EDR::LogBuilder::helper::GetDataByIndex(	// 자신 Processid 가져오기
									BuilderContext,
									0,
									&ProcessId_ptr,
									&Got_SIze
								))
									goto CleanUp;

								if (!EDR::LogBuilder::helper::GetDataByIndex(	// ParentProcessId가져오기
									BuilderContext,
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


									if (!EDR::Util::helper::Process_to_HASH(
										*(HANDLE*)ProcessId_ptr,
										&ImagePathNameBuffer,
										&ImagePathNameBufferMaxLen,
										&ImageSize,
										&ImageSha256Buffer,
										&ImageSha256Size
									))
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
											BuilderContext,
											(PUCHAR)SID_Buff,
											SID_Buff_Size
										);


										// 1) 경로 , 2) 사이즈 , 3) 해시

										// 자신 프로세스
										EDR::LogBuilder::LogBuilder_Append(
											BuilderContext,
											(PUCHAR)ImagePathNameBuffer,
											ImagePathNameBufferMaxLen
										);
										EDR::LogBuilder::LogBuilder_Append(
											BuilderContext,
											(PUCHAR)&ImageSize,
											sizeof(ImageSize)
										);
										EDR::LogBuilder::LogBuilder_Append(
											BuilderContext,
											(PUCHAR)ImageSha256Buffer,
											ImageSha256Size
										);

										// 부모 프로세스
										EDR::LogBuilder::LogBuilder_Append(
											BuilderContext,
											(PUCHAR)Parent_ImagePathNameBuffer,
											Parent_ImagePathNameBufferMaxLen
										);
										EDR::LogBuilder::LogBuilder_Append(
											BuilderContext,
											(PUCHAR)&Parent_ImageSize,
											sizeof(Parent_ImageSize)
										);
										EDR::LogBuilder::LogBuilder_Append(
											BuilderContext,
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
								BuilderContext,
								2,
								((PUCHAR*)&ImagePathBuffer),
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
									BuilderContext,
									(PUCHAR)&ImageSize,
									sizeof(ImageSize)
								);
								EDR::LogBuilder::LogBuilder_Append(
									BuilderContext,
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
								BuilderContext,
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
									BuilderContext,
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

						// 3. 로그 패키징 완료
						EDR::LogBuilder::LogBuilder_Closing(BuilderContext);

						// 4. 배치 버퍼로 이동 (Produce)
						// 이 함수 내부에서 해당 파이프라인의 Mutex만 사용하므로 병렬 처리됨
						resource::Produce::ProduceOnBatch(pPipeline, BuilderContext);

					CleanUp:
						{
							EDR::LogBuilder::LogBuilder_Remove(BuilderContext);
							EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(BuilderContext);
							BuilderContext = NULL;
						}
					}

					PsTerminateSystemThread(STATUS_SUCCESS);
				}
			}
		}

		// -----------------------------------------------------------------------------
		// [ Function Implementation ] - 로그 타입별 큐 할당 로직 포함
		// -----------------------------------------------------------------------------
		namespace function
		{
			// [Process Creation] -> 0번 큐
			BOOLEAN ProcessCreateLog(HANDLE ProcessId, ULONG64 NanoTimestamp, HANDLE Parent_ProcessId, PCUNICODE_STRING CommandLine)
			{
				PAGED_CODE();
				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::Process_Create, ProcessId, NanoTimestamp);
				if (!Context) return FALSE;

				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)&Parent_ProcessId, sizeof(Parent_ProcessId));
				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)CommandLine->Buffer, CommandLine->MaximumLength);

				// ProcessCreation 큐로 전송
				if (!LogPost::LogPut(resource::QueueTypes::ProcessCreation, Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					return FALSE;
				}
				return TRUE;
			}

			// [Process Terminate] -> 0번 큐 (ProcessCreation과 공유)
			BOOLEAN ProcessTerminateLog(HANDLE ProcessId, ULONG64 NanoTimestamp)
			{
				PAGED_CODE();
				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::Process_Terminate, ProcessId, NanoTimestamp);
				if (!Context) return FALSE;

				if (!LogPost::LogPut(resource::QueueTypes::ProcessCreation, Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					return FALSE;
				}
				return TRUE;
			}

			// [Image Load] -> 1번 큐
			BOOLEAN ImageLoadLog(HANDLE ProcessId, ULONG64 NanoTimestamp, PCUNICODE_STRING ImagePath)
			{
				PAGED_CODE();
				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::ImageLoad, ProcessId, NanoTimestamp);
				if (!Context) return FALSE;

				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)ImagePath->Buffer, ImagePath->MaximumLength);

				if (!LogPost::LogPut(resource::QueueTypes::ImageLoad, Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					return FALSE;
				}
				return TRUE;
			}

			// [Network WFP] -> 4번 큐
			BOOLEAN NetworkLog(HANDLE ProcessId, ULONG64 NanoTimestamp, PUCHAR SourceMacAddress, PUCHAR DestinationMacAddress,
				ULONG32 ProtocolNumber, BOOLEAN is_INBOUND, ULONG32 PacketSize,
				PUCHAR LOCAL_IP, ULONG32 LOCAL_IP_StrSIze, ULONG32 LOCAL_PORT,
				PUCHAR REMOTE_IP, ULONG32 REMOTE_IP_StrSIze, ULONG32 REMOTE_PORT,
				ULONG32 NetworkInterfaceIndex, PUCHAR PacketFrameBuffer)
			{
				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::Network, ProcessId, NanoTimestamp);
				if (!Context) return FALSE;

				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)&ProtocolNumber, sizeof(ProtocolNumber));
				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)&is_INBOUND, sizeof(is_INBOUND));
				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)&PacketSize, sizeof(PacketSize));
				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)&NetworkInterfaceIndex, sizeof(NetworkInterfaceIndex));
				EDR::LogBuilder::LogBuilder_Append(Context, SourceMacAddress, 18);
				EDR::LogBuilder::LogBuilder_Append(Context, DestinationMacAddress, 18);
				EDR::LogBuilder::LogBuilder_Append(Context, LOCAL_IP, LOCAL_IP_StrSIze + 1);
				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)&LOCAL_PORT, sizeof(LOCAL_PORT));
				EDR::LogBuilder::LogBuilder_Append(Context, REMOTE_IP, REMOTE_IP_StrSIze + 1);
				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)&REMOTE_PORT, sizeof(REMOTE_PORT));
				EDR::LogBuilder::LogBuilder_Append(Context, PacketFrameBuffer, PacketSize);

				if (!LogPost::LogPut(resource::QueueTypes::WFP, Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					return FALSE;
				}
				return TRUE;
			}

			// [Filesystem] -> 3번 큐
			BOOLEAN FilesystemLog(HANDLE ProcessId, ULONG64 NanoTimestamp, EDR::EventLog::Enum::FileSystem::Filesystem_enum FsEnum,
				UNICODE_STRING* Normalized_FilePath, UNICODE_STRING* To_Renmae_FilePath, PCHAR SHA256)
			{
				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::Filesystem, ProcessId, NanoTimestamp);
				if (!Context) return FALSE;

				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)&FsEnum, sizeof(FsEnum));
				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)Normalized_FilePath->Buffer, Normalized_FilePath->MaximumLength);

				if (To_Renmae_FilePath)
					EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)To_Renmae_FilePath->Buffer, To_Renmae_FilePath->MaximumLength);
				else
					EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)L"none", sizeof(L"none"));

				if (SHA256)
					EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)SHA256, 65); // SHA256
				else
					EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)"none", sizeof("none"));

				if (!LogPost::LogPut(resource::QueueTypes::Minifilter, Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					return FALSE;
				}
				return TRUE;
			}

			// [Registry] -> 2번 큐
			BOOLEAN Registry_by_CompleteorObjectNameLog(PCHAR KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp, PUNICODE_STRING Name)
			{
				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::Registry_CompleteNameLog, ProcessId, NanoTimestamp);
				if (!Context) return FALSE;

				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)KeyClass, (ULONG32)strlen(KeyClass) + 1);

				USHORT validDataSize = Name->Length;
				ULONG totalSizeWithNull = validDataSize + sizeof(WCHAR);
				PVOID tempBuffer = ExAllocatePoolWithTag(NonPagedPool, totalSizeWithNull, 'Tag1');
				if (tempBuffer) {
					RtlZeroMemory(tempBuffer, totalSizeWithNull);
					RtlCopyMemory(tempBuffer, Name->Buffer, validDataSize);
					EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)tempBuffer, totalSizeWithNull);
					ExFreePoolWithTag(tempBuffer, 'Tag1');
				}

				//if (!LogPost::LogPut(resource::QueueTypes::Registry, Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					return FALSE;
				}
				//return TRUE;
			}

			// [Registry] -> 2번 큐
			BOOLEAN Registry_by_OldNewNameLog(PCHAR KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp, PUNICODE_STRING Name, PUNICODE_STRING Old, PUNICODE_STRING New)
			{
				if (!Name || !Name->Buffer) return FALSE;

				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::Registry_OldNewLog, ProcessId, NanoTimestamp);
				if (!Context) return FALSE;

				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)KeyClass, (ULONG32)strlen(KeyClass) + 1);

				auto AppendSafe = [&](PUNICODE_STRING s) {
					if (s && s->Buffer) EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)s->Buffer, s->MaximumLength);
					else EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)L"none", sizeof(L"none"));
					};

				AppendSafe(Name);
				AppendSafe(Old);
				AppendSafe(New);

				//if (!LogPost::LogPut(resource::QueueTypes::Registry, Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					return FALSE;
				}
				//return TRUE;
			}

			// [ObCallback] -> 0번 큐 (Process 관련이므로) 또는 별도
			BOOLEAN ObRegisterCallbackLog(HANDLE ProcessId, ULONG64 NanoTimestamp, BOOLEAN is_CreateHandleInformation, ULONG32 DesiredAccess, HANDLE Target_ProcessId)
			{
				auto* Context = EDR::LogBuilder::helper::CreateEventLog(EDR::EventLog::Enum::ObRegisterCallback, ProcessId, NanoTimestamp);
				if (!Context) return FALSE;

				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)&DesiredAccess, sizeof(DesiredAccess));
				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)&is_CreateHandleInformation, sizeof(is_CreateHandleInformation));
				EDR::LogBuilder::LogBuilder_Append(Context, (PUCHAR)&Target_ProcessId, sizeof(Target_ProcessId));

				// ProcessCreation 큐 공유
				//if (!LogPost::LogPut(resource::QueueTypes::ProcessCreation, Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					return FALSE;
				}
				//return TRUE;
			}

			// [API Call] -> 0번 큐 또는 별도
			BOOLEAN API_CallLog(HANDLE ProcessId, ULONG64 NanoTimestamp, PCHAR JsonStr, ULONG32 JsonStrStrLen)
			{
				if (!JsonStr || !ProcessId || !NanoTimestamp) return FALSE;

				// API Call은 별도 구조체를 쓴다고 가정하에 작성된 기존 코드 유지
				// 단, 큐잉은 LogPost::LogPut 사용
				EDR::EventLog::Struct::ApiCall::EventLog_ApiCall* log = (EDR::EventLog::Struct::ApiCall::EventLog_ApiCall*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EDR::EventLog::Struct::ApiCall::EventLog_ApiCall), LogALLOC);
				if (!log) return FALSE;

				RtlZeroMemory(log, sizeof(EDR::EventLog::Struct::ApiCall::EventLog_ApiCall));
				log->header.Type = EDR::EventLog::Enum::apicall;
				log->header.ProcessId = ProcessId;
				log->header.NanoTimestamp = NanoTimestamp;
				// EDR::Util::SysVersion::GetSysVersion ... (생략)

				SIZE_T copyLen = JsonStrStrLen + 1 > 8192 ? 8192 : JsonStrStrLen;
				memcpy(log->body.Json, JsonStr, copyLen);

				// ProcessCreation 큐 공유
				if (!LogPost::LogPut(resource::QueueTypes::ProcessCreation, log))
				{
					ExFreePoolWithTag(log, LogALLOC);
					return FALSE;
				}
				return TRUE;
			}
		}
	}
}


/*#include "LogSender.hpp"

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

			// 1. 모든 큐 헤더 초기화
			for (int i = 0; i < QUEUE_COUNT; i++) {
				ExInitializeSListHead(&LogPost::g_QueueHeaders[i]);
			}

			for (int i = 0; i < QUEUE_COUNT; i++)
			{
				// 스레드 컨텍스트 할당 (어떤 큐를 맡을지 알려줌)
				auto* ctx = (LogPost::SystemThread_method::THREAD_CTX*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LogPost::SystemThread_method::THREAD_CTX), 'Thtx');
				if (ctx) {
					ctx->QueueType = (resource::QueueTypes)i; // 0: Process, 1: Image, ...

					HANDLE THREAD = NULL;
					NTSTATUS status = PsCreateSystemThread(
						&THREAD, THREAD_ALL_ACCESS, NULL, NULL, NULL,
						(PKSTART_ROUTINE)EDR::LogSender::LogPost::SystemThread_method::POST_SystemThread_method,
						ctx // 컨텍스트 전달
					);

					if (NT_SUCCESS(status) && THREAD) ZwClose(THREAD);
				}
			}

			return TRUE;
		}
		VOID CleanUp()
		{
			LogPost::CleanUpLogNodes();
		}

		namespace resource
		{

			namespace Produce
			{

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
				

			}
		}

		namespace LogPost
		{
			

			BOOLEAN is_LogPostWorking = false;

			#define QUEUE_COUNT 5 
			extern SLIST_HEADER g_QueueHeaders[QUEUE_COUNT];

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

			BOOLEAN LogPut(EDR::LogSender::resource::QueueTypes Type, PVOID log)
			{
				if (Type >= QUEUE_COUNT) return FALSE;

				USHORT NodeCount = QueryDepthSList(&g_QueueHeaders[Type]);
				if (NodeCount >= MAXIMUM_SLIST_NODE_SIZE) return FALSE; // 큐 꽉 참 (Drop)

				PLOG_QUEUE_NODE node = (PLOG_QUEUE_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LOG_QUEUE_NODE), Log_SLIST_ALLOC);
				if (!node) return FALSE;

				node->log = log;
				InterlockedPushEntrySList(&g_QueueHeaders[Type], &node->Entry);
				return TRUE;
			}

			BOOLEAN LogGet(EDR::LogSender::resource::QueueTypes Type, _Out_ PVOID* log)
			{
				if (Type >= QUEUE_COUNT || !log) return FALSE;

				*log = NULL;
				PSLIST_ENTRY Log_Entry = InterlockedPopEntrySList(&g_QueueHeaders[Type]);
				if (!Log_Entry) return FALSE;

				PLOG_QUEUE_NODE node = CONTAINING_RECORD(Log_Entry, LOG_QUEUE_NODE, Entry);
				*log = node->log;
				ExFreePoolWithTag(node, Log_SLIST_ALLOC);
				return TRUE;
			}

			namespace SystemThread_method
			{
				extern "C" VOID POST_SystemThread_method(PVOID Context)
				{
					auto* ThCtx = (THREAD_CTX*)Context;
					resource::QueueTypes MyQueueType = ThCtx->QueueType; // 내가 담당할 큐 타입

					// 컨텍스트 해제 (더 이상 필요 없음)
					ExFreePoolWithTag(ThCtx, 'Thtx');

					PAGED_CODE();

					while (is_LogPostWorking)
					{

						// 로그 가져오기
						PVOID CTX = NULL;
						if (!LogGet(MyQueueType ,&CTX))
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
							PsTerminateSystemThread(STATUS_SUCCESS);
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

				if (!LogPost::LogPut(resource::QueueTypes::ProcessCreation, Context))
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

				if (!LogPost::LogPut(resource::QueueTypes::ProcessCreation, Context))
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

				//if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				//return TRUE;
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

				//if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				//return TRUE;

				

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


				//if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				//return TRUE;
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

				
					[특이사항]
						CmRegistryCallbacks에서 얻은 { CompleteName의 Maximum 값은 널이상의 바이트 수가 책정될 수 있음. }
				
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

				//if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				//return TRUE;
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



				//if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				//return TRUE;
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



				//if (!LogPost::LogPut(Context))
				{
					EDR::LogBuilder::LogBuilder_Remove(Context);
					EDR::LogBuilder::Terminate_LOG_BUILDER_CTX(Context);
					Context = NULL;
					return FALSE;
				}

				//return TRUE;

				
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

				return TRUE;
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
				//if (!LogPost::LogPut(log))
				{
					ExFreePoolWithTag(log, LogALLOC);
					return FALSE;
				}

				//return TRUE;
			}

		}
	}
}*/