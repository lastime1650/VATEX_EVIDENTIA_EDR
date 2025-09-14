#include "NotifyRoutine.hpp"

namespace EDR
{
	namespace NotifyRoutines
	{
		NTSTATUS Load_NotifyRoutines()
		{
			NTSTATUS status;
			status = ProcessCreation::Load::Load_NotifyRoutine_ProcessCreate();
			if (!NT_SUCCESS(status))
			{
				CleanUp();
				return status;
			}

			status = ImageLoad::Load::Load_NotifyRoutine_ImageLoad();
			if (!NT_SUCCESS(status))
			{
				CleanUp();
				return status;
			}

			return status;
		}

		VOID CleanUp()
		{
			ProcessCreation::UnLoad::UnLoad_NotifyRoutine_ProcessCreate();
		}
	}
}