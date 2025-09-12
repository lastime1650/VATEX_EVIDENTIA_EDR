#include "util.hpp"

namespace EDR
{
	namespace Util
	{
		// 초 딜레이


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
