#include "EventLog.hpp"

namespace EDR
{
	namespace EventLog
	{
		namespace function
		{
			BOOLEAN Make_Header(
				Enum::EventLog_Enum type,
				HANDLE ProcessId,
				ULONG64 NanoTimestamp,

				_Inout_ Struct::EventLog_Header* out_header
			)
			{

				if (!out_header)
					return FALSE;

				BOOLEAN status = FALSE;

				out_header->Type = type;
				out_header->ProcessId = ProcessId;
				out_header->NanoTimestamp = NanoTimestamp;

				/* 
					SID 계정 식별 값
				
				PUNICODE_STRING SID = NULL;

				PCHAR ansi = NULL;
				ULONG32 ansi_size = 0;


				// 1. SID 유니코드 구하기
				EDR::Util::Account::SID::Get_PROCESS_SID(ProcessId, &SID);
				if (!SID)
					return FALSE;
				// 2. CHAR로 변환 ( ANSI  )
				EDR::Util::String::Unicode2Ansi::UnicodeString_to_ANSI(SID, &ansi, &ansi_size);
				if (!ansi_size)
					goto Cleanup;
				// 3. 구조체에 Copy (크기가 정적 사이즈보다 작으면 ansi_size만큼 복사
				RtlCopyMemory(out_header->Account.SID, ansi, sizeof(out_header->Account.SID) >= ansi_size ? ansi_size : sizeof(out_header->Account.SID));
				
				

				Cleanup:
				{
					if (ansi)
						EDR::Util::String::Unicode2Ansi::Release_UnicodeString_to_ANSI(ansi);

					if (SID)
						EDR::Util::Account::SID::Release_PROCESS_SID(SID);
				}
				*/
				status = TRUE;

				return status;
			}
		}
	}
}