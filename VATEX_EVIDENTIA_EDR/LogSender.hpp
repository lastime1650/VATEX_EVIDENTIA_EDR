#ifndef LOGSENDER_HPP
#define LOGSENDER_HPP

#include <ntifs.h>
#include "util.hpp"
#include "EventLog.hpp"
#include "APC.hpp"
#include "LogBuilder.hpp"

namespace EDR
{
	namespace LogSender
	{
		// -----------------------------------------------------------------------------
		// [ 메모리 태그 정의 ]
		// -----------------------------------------------------------------------------
#define LogALLOC        'LogA'
#define Log_SLIST_ALLOC 'LogS'
#define Prod_ALLOC      'Prod'
#define Pipe_ALLOC      'Pipe'

// -----------------------------------------------------------------------------
// [ 큐 타입 정의 ]
// -----------------------------------------------------------------------------
		namespace resource
		{
			enum QueueTypes
			{
				ProcessCreation = 0,
				ImageLoad,
				Registry,
				Minifilter,
				WFP,

				// 항상 마지막에 위치 (개수 카운트용)
				MaxCount
			};
		}

		// -----------------------------------------------------------------------------
		// [ 파이프라인 컨텍스트 구조체 ]
		// 입력(큐) -> 처리(스레드) -> 출력(배치버퍼)를 하나의 객체로 관리
		// -----------------------------------------------------------------------------
		typedef struct _LOG_PIPELINE_CTX {

			// 1. 식별자
			resource::QueueTypes Type;

			// 2. 입력 큐 (SLIST) - NonPaged
			SLIST_HEADER ListHead;

			// 3. 출력 배치 저장소 (Batch Buffer) - Paged
			FAST_MUTEX   BatchMtx;       // 출력 버퍼 보호용 락
			PUCHAR       BatchBuffer;    // 실제 로그 데이터가 모이는 곳
			SIZE_T       BatchSize;      // 현재 버퍼 크기

			// 4. 스레드 관리
			HANDLE       ThreadHandle;   // 전담 워커 스레드 핸들

		} LOG_PIPELINE_CTX, * PLOG_PIPELINE_CTX;

		// 전역 파이프라인 배열 (5개)
		extern LOG_PIPELINE_CTX g_Pipelines[resource::MaxCount];

		// -----------------------------------------------------------------------------
		// [ 전역 함수 ]
		// -----------------------------------------------------------------------------
		BOOLEAN INITIALIZE();
		VOID CleanUp();

		namespace resource
		{
			// 큐 노드 구조체
			typedef struct _LOG_NODE {
				SLIST_ENTRY Entry;
				PVOID       UserSpace; // (Legacy) 
				SIZE_T      UserSpaceSize;
			} LOG_NODE, * PLOG_NODE;

			namespace Produce
			{
				// 파이프라인의 배치 버퍼에 데이터를 기록하는 함수
				BOOLEAN ProduceOnBatch(PLOG_PIPELINE_CTX pPipeline, EDR::LogBuilder::PLOG_BUILDER_CTX context);
			}

			namespace Consume
			{
				// 유저 모드가 특정 파이프라인의 데이터를 가져가는 함수
				BOOLEAN ConsumeV2(resource::QueueTypes Type, _In_ HANDLE RequestProcessId, _Out_ PVOID* AllocatedUser, _Out_ ULONG64* Size);
			}
		}

		namespace LogPost
		{
			extern BOOLEAN is_LogPostWorking;

			// 내부 큐 노드 구조체
			typedef struct _LOG_QUEUE_NODE {
				SLIST_ENTRY Entry;
				PVOID       log; // LogBuilder Context
			} LOG_QUEUE_NODE, * PLOG_QUEUE_NODE;

			// -------------------------------------------------------------------------
			// [ 큐 조작 함수 ]
			// -------------------------------------------------------------------------
			// 특정 타입의 파이프라인 큐에 넣기
			BOOLEAN LogPut(resource::QueueTypes Type, PVOID log);

			// 특정 파이프라인 큐에서 꺼내기 (내부용)
			BOOLEAN LogGet(PLOG_PIPELINE_CTX pPipeline, _Out_ PVOID* log);

			VOID CleanUpLogNodes();

			namespace SystemThread_method
			{
				// 워커 스레드 메인 함수
				extern "C" VOID POST_SystemThread_method(PVOID Context);
			}
		}

		// -----------------------------------------------------------------------------
		// [ 로그 생성 함수들 ] - 각 기능별 로그 수집 인터페이스
		// -----------------------------------------------------------------------------
		namespace function
		{
			BOOLEAN ProcessCreateLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,
				HANDLE Parent_ProcessId,
				PCUNICODE_STRING CommandLine
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
				UNICODE_STRING* Normalized_FilePath,
				UNICODE_STRING* To_Renmae_FilePath,
				PCHAR SHA256
			);

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
			);

			BOOLEAN Registry_by_CompleteorObjectNameLog(
				PCHAR KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp,
				PUNICODE_STRING Name
			);

			BOOLEAN Registry_by_OldNewNameLog(
				PCHAR KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp,
				PUNICODE_STRING Name, PUNICODE_STRING Old, PUNICODE_STRING New
			);

			BOOLEAN ObRegisterCallbackLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,
				BOOLEAN is_CreateHandleInformation,
				ULONG32 DesiredAccess,
				HANDLE Target_ProcessId
			);

			BOOLEAN API_CallLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,
				PCHAR JsonStr,
				ULONG32 JsonStrStrLen
			);
		}
	}
}

#endif // LOGSENDER_HPP

/*
#ifndef LOGSENDER_HPP
#define LOGSENDER_HPP

#include "util.hpp"
#include "EventLog.hpp"
#include "APC.hpp"
#include "LogBuilder.hpp"
namespace EDR
{

	namespace LogSender
	{
		extern PUCHAR CollapseProducedLogs_StartAddress;
		extern PUCHAR CollapseProducedLogs_CurrentAddress;
		extern SIZE_T CollapseProducedLogs_Size;
		extern FAST_MUTEX CollapseProduceLogs_Mtx;

		#define MAXIMUM_SLIST_NODE_SIZE 65535

		BOOLEAN INITIALIZE();
		VOID CleanUp();


		namespace resource
		{
			enum QueueTypes
			{
				ProcessCreation,
				ImageLoad,
				Registry,
				Minifilter,
				WFP
			};

			




			extern BOOLEAN is_consume_working;

			typedef struct _LOG_NODE {
				SLIST_ENTRY Entry;
				ULONG64 Type;
				PVOID   UserSpace;
				SIZE_T  UserSpaceSize;
			} LOG_NODE, * PLOG_NODE;

			namespace Produce
			{

				BOOLEAN ProduceOnBatch(EDR::LogBuilder::PLOG_BUILDER_CTX context);
			}
			namespace Consume
			{
				BOOLEAN ConsumeV2(_In_ HANDLE RequestProcessId, _Out_ PVOID* AllocatedUser, _Out_ ULONG64* Size);
			}

		}

		namespace LogPost
		{
			#define QUEUE_COUNT 5 
			extern SLIST_HEADER g_QueueHeaders[QUEUE_COUNT];

			#define LogALLOC 'Log'
			#define LogPostCtxALLOC 'LogP'

			#define Log_SLIST_ALLOC 'SLog'

			extern BOOLEAN is_LogPostWorking;
			extern SLIST_HEADER g_LogPostListHead; // 로그 저장 큐

			typedef struct _LOG_QUEUE_NODE {
				SLIST_ENTRY Entry;
				PVOID log; // allocated log
			} LOG_QUEUE_NODE, * PLOG_QUEUE_NODE;


			BOOLEAN LogPut(EDR::LogSender::resource::QueueTypes Type, PVOID log);
			BOOLEAN LogGet(EDR::LogSender::resource::QueueTypes Type, _Out_ PVOID* log);
			VOID CleanUpLogNodes();
			

			namespace SystemThread_method
			{
				struct THREAD_CTX {
					EDR::LogSender::resource::QueueTypes QueueType;
				};

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

				HANDLE Parent_ProcessId,
				PCUNICODE_STRING CommandLine
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

				UNICODE_STRING* To_Renmae_FilePath, // if NULL< not Rename.
				PCHAR SHA256 // if NULL not Calculate SHA256
				
			);

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
			);

			// Registry
			BOOLEAN Registry_by_CompleteorObjectNameLog(
				PCHAR KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp,
				PUNICODE_STRING Name
			);
			BOOLEAN Registry_by_OldNewNameLog (
				PCHAR KeyClass, HANDLE ProcessId, ULONG64 NanoTimestamp,
				PUNICODE_STRING Name, PUNICODE_STRING Old, PUNICODE_STRING New
			);

			//ObRegisterCallback
			BOOLEAN ObRegisterCallbackLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				BOOLEAN is_CreateHandleInformation,
				ULONG32 DesiredAccess,
				HANDLE Target_ProcessId
			);

			// api call
			BOOLEAN API_CallLog(
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				PCHAR JsonStr,
				ULONG32 JsonStrStrLen // without null
			);
		}

	}
}

#endif*/