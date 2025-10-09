#ifndef OB_REGISETERS_CALLBACK_H
#define OB_REGISETERS_CALLBACK_H

#include "util.hpp"




#define ObRegisterCallbacks_Altitude L"16501"

namespace EDR
{
	namespace ObRegisterCallback
	{
		namespace Handler
		{
			extern "C" OB_PREOP_CALLBACK_STATUS PreOperationCallback(
				_In_ PVOID RegistrationContext,
				_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
			);
		}
		NTSTATUS Load_ObRegisterCallbacks();
		VOID CleanUp_ObRegisterCallbacks();
	}
}

#endif