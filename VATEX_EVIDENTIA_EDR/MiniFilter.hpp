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
				// PRE -> POST ���� ������ ���� ���ؽ�Ʈ ����ü
				typedef struct _PRE_TO_POST_CONTEXT {
					PFLT_FILE_NAME_INFORMATION OriginalNameInfo; // ���� ���� �̸� ����
					PUNICODE_STRING NewFileName;                 // �̸� ���� �� �� ���� �̸� (���� �Ҵ� �ʿ�)
					CHAR Behavior[20];                           // ���� (��: "rename", "delete")
				} PRE_TO_POST_CONTEXT, * PPRE_TO_POST_CONTEXT;

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
			// ���� �ؽñ��ϱ�
			BOOLEAN Get_FileSHA256(
				_In_ PFLT_INSTANCE Instance,
				_In_ PFILE_OBJECT FileObject,
				_Inout_ PCHAR Inout_SHABuffer, // �ּ� SHA256_BINARY_LENGTH ����Ʈ
				_Out_ ULONG64* Out_FileSize
			);

			// ���� �ؽñ��ϱ� - B
			BOOLEAN Get_FileSHA256_by_FILEPATH(
				PUNICODE_STRING FilePath,
				PSIZE_T FileSize,
				PCHAR Allocated_SHA256
			);

			// ���� ������ ���ϱ�
			BOOLEAN Get_FileSize(
				_In_ PFLT_INSTANCE Instance,
				_In_ PFILE_OBJECT FileObject,
				_Inout_ ULONG64* Out_FIleSize
			);

			// ���Ͽ��� Ȯ�� �� �̸� ���� ���� ( ����� "Relase_Is_File_with_Get_File_Info" ȣ�� �ʼ�
			BOOLEAN Is_File_with_Get_File_Info(
				PFLT_CALLBACK_DATA Input_Data, // �ڵ鷯���� ���� ����
				PFLT_FILE_NAME_INFORMATION* Output_fileNameInfo // ���� ��ȯ (�ƴϸ� �״�� ���� ) 
			);
			VOID Relase_Is_File_with_Get_File_Info(PFLT_FILE_NAME_INFORMATION fileNameInfo);

		}

		

		NTSTATUS Load_MiniFilter(PDRIVER_OBJECT DriverObject);
		VOID CleanUp_MiniFilter();
	}
}

#endif