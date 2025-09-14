#include "DriverUnload.hpp"

// FREE_Cleanup - Resource Headers
#include "APC.hpp"
#include "IOCTL.hpp"
#include "NotifyRoutine.hpp"
#include "LogSender.hpp"
#include "Network.hpp"

namespace EDR
{
	namespace UnLoad
	{
		VOID DRIVER_UNLOAD(_In_ struct _DRIVER_OBJECT* DriverObject)
		{
			UNREFERENCED_PARAMETER(DriverObject);
			
			// LogSender 秦力
			EDR::LogSender::CleanUp();

			// IOCTL 秦力
			EDR::IOCTL::CleanUp_IOCTL();

			// APC 秦力
			EDR::APC::CleanUp_APC();

			// NotifyRoutines 秦力
			EDR::NotifyRoutines::CleanUp();
			
			// Network 秦力
			EDR::WFP_Filter::Cleanup_WFP_Filter();

			return;
		}
	}
}