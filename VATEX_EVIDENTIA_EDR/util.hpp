#ifndef UITL_HPP
#define UITL_HPP

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#pragma warning (disable : 4201) 
#pragma warning (disable : 4083) 
#pragma warning (disable : 4005) 
#pragma warning (disable : 4100)
#pragma warning (disable : 5040)
#pragma warning (disable : 4083)
#pragma warning (disable : 4996)
#pragma warning (disable : 4189)
#include <intrin.h>
#define INITGUID
#include <guiddef.h>

#define debug_log(text, ...) (DbgPrintEx(0, 0, /*xs*/(text), ##__VA_ARGS__))
#define debug_break() __debugbreak();

#include "ProcessUtil.hpp"

namespace EDR
{
	namespace Util
	{
		// √  µÙ∑π¿Ã

		namespace IRQL
		{
			BOOLEAN is_PASSIVE_LEVEL();
		}
		

		namespace Timestamp
		{
			ULONG64 Get_LocalTimestamp_Nano();
		}
	}
}


#endif