#ifndef REGISTRY_HP
#define REGISTRY_HP

#include "util.hpp"
#define RegistryAltitude L"31650"

namespace EDR
{
	namespace Registry
	{
		namespace resource
		{
			extern BOOLEAN is_complete_init;
			extern LARGE_INTEGER Cookie_for_unload;
		}

		namespace Handler
		{
			extern "C" NTSTATUS RegisterCallbacksHandler(
				_In_ PVOID CallbackContext,
				_In_opt_ PVOID Argument1,
				_In_opt_ PVOID Argument2
			);
		}

		NTSTATUS Load_RegistryCallback(PDRIVER_OBJECT driverobject);
		VOID CleanUp_RegistryCallback();

	}
}


#endif