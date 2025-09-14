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
			
			// LogSender ����
			EDR::LogSender::CleanUp();

			// IOCTL ����
			EDR::IOCTL::CleanUp_IOCTL();

			// APC ����
			EDR::APC::CleanUp_APC();

			// NotifyRoutines ����
			EDR::NotifyRoutines::CleanUp();
			
			// Network ����
			EDR::WFP_Filter::Cleanup_WFP_Filter();

			return;
		}
	}
}