#ifndef NOTIFYROUTINE_H
#define NOTIFYROUTINE_H

#include "util.hpp"

#include "NotifyRoutine_ImageLoad.hpp"
#include "NotifyRoutine_ProcessCreation.hpp"

namespace EDR
{
	namespace NotifyRoutines
	{
		NTSTATUS Load_NotifyRoutines();
		VOID CleanUp();
	}
}

#endif