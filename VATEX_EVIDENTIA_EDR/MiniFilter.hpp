#ifndef MiNiFilter_H
#define MiNiFilter_H

#include "util.hpp"
#include <fltKernel.h>

//#define Minifilter_Altitude L"16502"

namespace EDR
{
	namespace MiniFilter
	{
		namespace resource
		{
			extern PFLT_FILTER gFilterHandle;

			#define PretoPost_CTX_ALLOC_TAG 'PTPC'
			typedef struct _PretoPost_CTX
			{
				PWCH NormalizedFilePath;
				ULONG64 timestamp;
				HANDLE ProcessId;

				EDR::EventLog::Enum::FileSystem::Filesystem_enum Action; // recently ) create

			}PretoPost_CTX, *PPretoPost_CTX;

			#define FLT_WORKITEM_CTX_ALLOC_TAG 'FWCT'
			typedef struct _HASH_WORK_ITEM_CONTEXT_DETAILS
			{
				PFLT_INSTANCE Instance;             // 파일 작업을 위한 인스턴스
				PFILE_OBJECT FileObject;            // 해싱할 파일 객체
				HANDLE ProcessId;                    // 요청 프로세스 ID
				ULONG64 timestamp;            // 이벤트 타임스탬프
				EDR::EventLog::Enum::FileSystem::Filesystem_enum Action; // 작업 종류 (open/create)
				PWCH NormalizedFilePath;
			}HASH_WORK_ITEM_CONTEXT_DETAILS, *PHASH_WORK_ITEM_CONTEXT_DETAILS;

			typedef struct _HASH_WORK_ITEM_CONTEXT {
				PFLT_GENERIC_WORKITEM  WorkItem;     // FltQueueGenericWorkItem에 필요한 구조체
				PHASH_WORK_ITEM_CONTEXT_DETAILS Details;
			} HASH_WORK_ITEM_CONTEXT, * PHASH_WORK_ITEM_CONTEXT;
		}

		namespace Handler
		{
			namespace PRE
			{
				extern "C" FLT_PREOP_CALLBACK_STATUS
					PRE_filter_Handler(
						PFLT_CALLBACK_DATA Data,
						PCFLT_RELATED_OBJECTS FltObjects,
						EDR::MiniFilter::resource::PPretoPost_CTX* CompletionContext
					);

			}
			namespace POST
			{
				namespace FltWorkItem
				{
					

					extern "C"  VOID FltWorkItemThread(
						_In_ PFLT_GENERIC_WORKITEM FltWorkItem,
						_In_ PVOID FltObject,
						_In_opt_ PVOID Context
					);

				}

				extern "C" FLT_POSTOP_CALLBACK_STATUS 
					POST_filter_Handler(
						PFLT_CALLBACK_DATA Data,
						PCFLT_RELATED_OBJECTS FltObjects,
						EDR::MiniFilter::resource::PPretoPost_CTX CompletionContext,
						FLT_POST_OPERATION_FLAGS Flags
					);
			}
		}

		namespace helper
		{
			// 파일 해시구하기
			BOOLEAN Get_FileSHA256(
				_In_ PFLT_INSTANCE Instance,
				_In_ PFILE_OBJECT FileObject,
				_Inout_ PCHAR Inout_SHABuffer, // 최소 SHA256_BINARY_LENGTH 바이트
				_Out_ ULONG64* Out_FileSize
			);

			// 파일 해시구하기 - B
			BOOLEAN Get_FileSHA256_by_FILEPATH(
				PUNICODE_STRING FilePath,
				PSIZE_T FileSize,
				PCHAR Allocated_SHA256
			);

			// 파일 사이즈 구하기
			BOOLEAN Get_FileSize(
				_In_ PFLT_INSTANCE Instance,
				_In_ PFILE_OBJECT FileObject,
				_Inout_ ULONG64* Out_FIleSize
			);

			// 파일여부 확인 및 이름 정보 추출 ( 추출시 "Relase_Is_File_with_Get_File_Info" 호출 필수
			BOOLEAN Is_File_with_Get_File_Info(
				PFLT_CALLBACK_DATA Input_Data, // 핸들러에서 얻은 정보
				PFLT_FILE_NAME_INFORMATION* Output_fileNameInfo // 정보 반환 (아니면 그대로 냅둔 ) 
			);
			VOID Relase_Is_File_with_Get_File_Info(PFLT_FILE_NAME_INFORMATION fileNameInfo);

		}

		

		NTSTATUS Load_MiniFilter(PDRIVER_OBJECT DriverObject);
		VOID CleanUp_MiniFilter();
	}
}

#endif