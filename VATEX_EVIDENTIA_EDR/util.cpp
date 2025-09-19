#include "util.hpp"

namespace EDR
{
	namespace Util
	{
		// �� ������
		namespace SysVersion
		{
			CHAR Version[256] = { 0 };
			ULONG32 VersionStrSize = 0;

			NTSTATUS VersionCheck()
			{
				NTSTATUS status = STATUS_SUCCESS;

				/*
					�� OS���� ������
				*/
				RTL_OSVERSIONINFOW os_version_info = { 0, };
				os_version_info.dwOSVersionInfoSize = sizeof(PRTL_OSVERSIONINFOW);

				// RtlGetVersion�� ����Ͽ� OS ���� ���� ��������
				status = RtlGetVersion(&os_version_info);
				if (status != STATUS_SUCCESS)
					return FALSE;
				/*
					OS���� üũ if
				*/
				if (os_version_info.dwMajorVersion >= 10) {
					// Windows 10 �̻�
					status = STATUS_SUCCESS;

					RtlZeroMemory(Version, 0);
					RtlStringCchPrintfA(
						Version,
						RTL_NUMBER_OF(Version),
						"%lu.%lu (Build %lu), Platform: %lu, CSD: %ws",
						os_version_info.dwMajorVersion,
						os_version_info.dwMinorVersion,
						os_version_info.dwBuildNumber,
						os_version_info.dwPlatformId,
						os_version_info.szCSDVersion
					);
				VersionStrSize = (ULONG32)strlen(Version) + 1;
				}
				else {
					// Windows 10�̸�
					status = STATUS_NOT_SUPPORTED;
				}
				return status;
			}

			ULONG32 GetSysVersion(PCHAR in_Buffer, ULONG32 in_BufferSize)
			{
				if (!VersionStrSize)
				{
					return 0;
				}

				RtlCopyMemory(
					in_Buffer,
					Version,
					in_BufferSize > VersionStrSize ? VersionStrSize : (in_BufferSize - 1)
				);

				return VersionStrSize;
			}
		}

		namespace IRQL
		{
			BOOLEAN is_PASSIVE_LEVEL()
			{
				if (KeGetCurrentIrql() == PASSIVE_LEVEL)
					return TRUE;
				else
					return FALSE;
			}
		}

		namespace Timestamp
		{
			ULONG64 Get_LocalTimestamp_Nano()
			{
				LARGE_INTEGER systemtime;
				LARGE_INTEGER localtime;

				KeQuerySystemTimePrecise(&systemtime);

				// 2. �ý��� �ð��� ���� �ð����� ��ȯ
				ExSystemTimeToLocalTime(&systemtime, &localtime);


				return ((ULONG64)localtime.QuadPart * 100ULL) ;
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

				// ���� �а� �ؽ� ���ϱ�
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
					ansi_sz > BUfferSIze ? BUfferSIze : (ansi_sz - 1)
				);

				EDR::Util::String::Unicode2Ansi::Release_UnicodeString_to_ANSI(ansi);
				return TRUE;
			}

			BOOLEAN Process_to_HASH(HANDLE ProcessId, CHAR* out_ImagePathNameBuffer, SIZE_T in_ImagePathNameBufferSIze, SIZE_T* out_ImageFileSize, CHAR* out_SHA256Buffer, SIZE_T SHA256BufferSize)
			{
				// 1. ���μ��� �ڵ� ���
				HANDLE ProcessHandle = NULL;
				EDR::Util::Process::Handle::LookupProcessHandlebyProcessId(ProcessId, &ProcessHandle);
				if (!ProcessHandle)
					return FALSE;

				// 2. ���μ��� �̹��� ������ ���
				PUNICODE_STRING Process_ImagePath = NULL;
				EDR::Util::Process::ImagePath::LookupProcessAbsoluteImagePathbyProcessHandle(ProcessHandle, &Process_ImagePath);
				if (!Process_ImagePath)
				{
					EDR::Util::Process::Handle::ReleaseLookupProcessHandlebyProcessId(ProcessHandle);
					return FALSE;
				}

				// 3. ���μ��� �̹��� �ؽÿ� ����ũ�� ���
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
				if (!NT_SUCCESS(EDR::Util::File::Read::ReadFile(*UnicodeImagePath, &FileBin, &FileBInSz)))
					return FALSE;

				PCHAR SHA256 = NULL;
				ULONG SHA256_sz = EDR::Util::Hash::SHA256::SHA256_Hasing(&SHA256, FileBin, FileBInSz);
				if (!SHA256_sz || !SHA256)
				{
					EDR::Util::File::Release_File(FileBin);
					return FALSE;
				}

				RtlCopyMemory(inout_SHA256Buffer, SHA256, SHA256_sz > SHA256BufferSize ? SHA256BufferSize - 1 : SHA256_sz);

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
								SID ����
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


#define NDIS630
#include <fwpsk.h>


namespace EDR
{
	namespace Util
	{
		namespace helper
		{
			NTSTATUS GetInterfaceNameFromIndex_Ansi(
				_In_ ULONG InterfaceIndex,
				_Out_writes_bytes_(NameBufferSize) PCHAR outNameBuffer,
				_In_ ULONG NameBufferSize
			)
			{
				// �� �Լ��� �ݵ�� PASSIVE_LEVEL���� ȣ��Ǿ�� ���� ���
				PAGED_CODE();

				if (outNameBuffer == NULL || NameBufferSize == 0)
				{
					return STATUS_INVALID_PARAMETER;
				}

				NTSTATUS status = STATUS_UNSUCCESSFUL;
				PMIB_IF_ROW2 pIfRow = NULL;

				// 1. MIB_IF_ROW2 ����ü�� ���� �޸𸮸� NonPagedPool���� �Ҵ��մϴ�.
				//    GetIfEntry2�� �� ����ü�� ä���ݴϴ�.
				pIfRow = (PMIB_IF_ROW2)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(MIB_IF_ROW2), 'IFR2');
				if (pIfRow == NULL)
				{
					return STATUS_INSUFFICIENT_RESOURCES;
				}

				// ����ü�� 0���� �ʱ�ȭ
				RtlZeroMemory(pIfRow, sizeof(MIB_IF_ROW2));

				// 2. ��ȸ�� �������̽��� �ε����� �����մϴ�.
				pIfRow->InterfaceIndex = InterfaceIndex;

				// 3. GetIfEntry2 �Լ��� ȣ���Ͽ� pIfRow�� ä��ϴ�.
				//    �� �Լ��� PASSIVE_LEVEL������ ȣ�� �����մϴ�.
				status = GetIfEntry2(pIfRow);
				if (!NT_SUCCESS(status))
				{
					ExFreePool(pIfRow);
					return status;
				}

				// 4. ���������� ������ ����������, pIfRow->Alias ��� (UNICODE_STRING)��
				//    �츮�� ���ϴ� Ansi ���ڿ��� ��ȯ�մϴ�.
				UNICODE_STRING alias;
				RtlInitUnicodeString(&alias, pIfRow->Alias);
				ANSI_STRING ansiName;
				status = RtlUnicodeStringToAnsiString(&ansiName, &alias, TRUE); // TRUE: �޸� �Ҵ�
				if (!NT_SUCCESS(status))
				{
					ExFreePool(pIfRow);
					return status;
				}

				// 5. ��ȯ�� Ansi ���ڿ��� ��� ���۷� �����ϰ� �����մϴ�.
				RtlStringCchCopyA(outNameBuffer, NameBufferSize, ansiName.Buffer);

				// 6. RtlUnicodeStringToAnsiString�� �Ҵ��� �޸𸮸� �����մϴ�.
				RtlFreeAnsiString(&ansiName);

				// 7. GetIfEntry2�� ���� �Ҵ��ߴ� �޸𸮸� �����մϴ�.
				ExFreePool(pIfRow);

				return STATUS_SUCCESS;
			}
		}
	}
}

