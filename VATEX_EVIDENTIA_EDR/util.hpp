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
#include "Shared.hpp"

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

		namespace helper
		{

			
			// 버퍼는 충분히 공간이 사전에 있어야함
			BOOLEAN CHAR_to_FILESIZE(PCHAR FIlePathBuffer, ULONG32 FIlePathBufferSize, SIZE_T* FileSize);
			BOOLEAN CHAR_to_HASH(PCHAR FIlePathBuffer, ULONG32 FIlePathBufferSize, PCHAR out_HASHBUFFER, SIZE_T* out_FileSize);
			BOOLEAN UNICODE_to_CHAR(PUNICODE_STRING input, CHAR* Buffer, SIZE_T BUfferSIze);
			BOOLEAN Process_to_HASH(HANDLE ProcessId, CHAR* out_ImagePathNameBuffer, SIZE_T in_ImagePathNameBufferSIze, SIZE_T* out_ImageFileSize, CHAR* out_SHA256Buffer, SIZE_T SHA256BufferSize);
			BOOLEAN FilePath_to_HASH(PUNICODE_STRING UnicodeImagePath, SIZE_T* out_ImageFileSize, CHAR* inout_SHA256Buffer, SIZE_T SHA256BufferSize);
			BOOLEAN Process_to_CHAR(HANDLE ProcessHandle, CHAR* Buffer, SIZE_T BUfferSIze);
			BOOLEAN SID_to_CHAR(HANDLE ProcessId, CHAR* Buffer, SIZE_T BUfferSIze);
			// 부가적
			NTSTATUS GetInterfaceNameFromIndex_Ansi(
				_In_ ULONG InterfaceIndex,
				_Out_writes_bytes_(NameBufferSize) PCHAR outNameBuffer,
				_In_ ULONG NameBufferSize
			);
		}
	}
}




#endif