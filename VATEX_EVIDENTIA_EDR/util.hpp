#ifndef UITL2_HPP
#define UITL2_HPP

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
#include <ntstrsafe.h>

#define debug_log(text, ...) (DbgPrintEx(0, 0, /*xs*/(text), ##__VA_ARGS__))
#define debug_break() __debugbreak();

#include "EventLog.hpp"
#include "ProcessUtil.hpp"
#include "Account.hpp"
#include "HASH.hpp"
#include "FileJob.hpp"
#include "String_.hpp"
#include "User.hpp"

namespace EDR
{
	namespace Util
	{

		namespace IRQL
		{
			BOOLEAN is_PASSIVE_LEVEL();
		}
		

		namespace Timestamp
		{
			ULONG64 Get_LocalTimestamp_Nano();
		}

		namespace SysVersion
		{
			extern CHAR Version[256];
			extern ULONG32 VersionStrSize;
			NTSTATUS VersionCheck();
			ULONG32 GetSysVersion(PCHAR in_Buffer, ULONG32 in_BufferSize);
		}

	}
}


#endif