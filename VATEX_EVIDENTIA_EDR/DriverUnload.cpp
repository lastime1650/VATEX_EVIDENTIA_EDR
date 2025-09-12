#include "DriverUnload.hpp"

// FREE_Cleanup - Resource Headers
#include "APC.hpp"
#include "IOCTL.hpp"

namespace EDR
{
	namespace UnLoad
	{
		VOID DRIVER_UNLOAD(_In_ struct _DRIVER_OBJECT* DriverObject)
		{
			UNREFERENCED_PARAMETER(DriverObject);
			
			// IOCTL ����
			EDR::IOCTL::CleanUp_IOCTL();

			// APC ����
			EDR::APC::CleanUp_APC();
			
			return;
		}
	}
}