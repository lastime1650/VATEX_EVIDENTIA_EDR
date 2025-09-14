#include "util.hpp"

namespace EDR
{
	namespace Util
	{
		// 초 딜레이
		namespace SysVersion
		{
			CHAR Version[256] = { 0 };
			ULONG32 VersionStrSize = 0;

			NTSTATUS VersionCheck()
			{
				NTSTATUS status = STATUS_SUCCESS;

				/*
					현 OS버전 가져옴
				*/
				RTL_OSVERSIONINFOW os_version_info = { 0, };
				os_version_info.dwOSVersionInfoSize = sizeof(PRTL_OSVERSIONINFOW);

				// RtlGetVersion을 사용하여 OS 버전 정보 가져오기
				status = RtlGetVersion(&os_version_info);
				if (status != STATUS_SUCCESS)
					return FALSE;
				/*
					OS버전 체크 if
				*/
				if (os_version_info.dwMajorVersion >= 10) {
					// Windows 10 이상
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
					// Windows 10미만
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

				// 2. 시스템 시간을 로컬 시간으로 변환
				ExSystemTimeToLocalTime(&systemtime, &localtime);


				return ((ULONG64)localtime.QuadPart * 100ULL) ;
			}
		}
	}
}
