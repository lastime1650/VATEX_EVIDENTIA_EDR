#include "NotifyRoutine_ImageLoad.hpp"

namespace EDR
{
	namespace NotifyRoutines
	{
		namespace Handler
		{
			extern "C" VOID PLoadImageNotifyRoutine(
				PUNICODE_STRING FullImageName,
				HANDLE ProcessId,
				PIMAGE_INFO ImageInfo
			)
			{
				if (!FullImageName)
					return;
				if (!EDR::Util::Shared::USER_AGENT::ProcessId)
					return;
				PAGED_CODE();

				ULONG64 NanoTimestamp = EDR::Util::Timestamp::Get_LocalTimestamp_Nano();
				
				EDR::LogSender::function::ImageLoadLog(
					ProcessId,
					NanoTimestamp,
					FullImageName
				);

			}
		}

		namespace ImageLoad
		{

			BOOLEAN is_complete_init = FALSE;
			namespace Load
			{
				NTSTATUS Load_NotifyRoutine_ImageLoad()
				{
					NTSTATUS status = PsSetLoadImageNotifyRoutine(Handler::PLoadImageNotifyRoutine);
					if (!NT_SUCCESS(status))
						is_complete_init = FALSE;
					else
						is_complete_init = TRUE;
					
					return status;
				}
			}
			namespace UnLoad
			{
				VOID UnLoad_NotifyRoutine_ImageLoad()
				{
					if (is_complete_init)
						PsRemoveLoadImageNotifyRoutine(Handler::PLoadImageNotifyRoutine);
				}
			}




		}
	}
}