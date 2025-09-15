#include "DriverUnload.hpp"

// FREE_Cleanup - Resource Headers
#include "APC.hpp"
#include "IOCTL.hpp"
#include "NotifyRoutine.hpp"
#include "LogSender.hpp"
#include "Network.hpp"
#include "MiniFilter.hpp"
#include "Registry.hpp"
#include "ObRegisterCallback.hpp"

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

			// Minifilter ����
			EDR::MiniFilter::CleanUp_MiniFilter();

			// RegistryCallback ����
			EDR::Registry::CleanUp_RegistryCallback();

			// ObRegisterCallback ����
			EDR::ObRegisterCallback::CleanUp_ObRegisterCallbacks();

			return;
		}
	}
}