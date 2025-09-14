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
	}
}
