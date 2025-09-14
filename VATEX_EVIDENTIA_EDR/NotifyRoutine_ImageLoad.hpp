#ifndef NOTIFYROUTINE_IMAGE_H
#define NOTIFYROUTINE_IMAGE_H

#include "util.hpp"
#include "LogSender.hpp"

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
			);
		}

		namespace ImageLoad
		{


			namespace Load
			{
				NTSTATUS Load_NotifyRoutine_ImageLoad();
			}
			namespace UnLoad
			{
				VOID UnLoad_NotifyRoutine_ImageLoad();
			}




		}
	}
}

#endif