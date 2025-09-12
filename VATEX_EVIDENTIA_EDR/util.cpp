#include "util.hpp"

namespace EDR
{
	namespace Util
	{
		// �� ������


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
