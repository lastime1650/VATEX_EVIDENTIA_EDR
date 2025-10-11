#include "DriverUnload.hpp"

// FREE_Cleanup - Resource Headers
#include "IOCTL.hpp"
#include "NotifyRoutine.hpp"
#include "LogSender.hpp"
#include "Network.hpp"
#include "MiniFilter.hpp"
#include "Registry.hpp"
#include "ObRegisterCallback.hpp"
//#include "Response.hpp"
#include "DLP.hpp"
namespace EDR
{
	namespace UnLoad
	{
		VOID DRIVER_UNLOAD(_In_ struct _DRIVER_OBJECT* DriverObject)
		{
			UNREFERENCED_PARAMETER(DriverObject);
			
			// LogSender 해제
			EDR::LogSender::CleanUp();

			// IOCTL 해제
			EDR::IOCTL::CleanUp_IOCTL();

			// Response 해시테이블 해제
			//EDR::Response::HashTable::CleanUp();

			// NotifyRoutines 해제
			EDR::NotifyRoutines::CleanUp();
			
			// Network 해제
			EDR::WFP_Filter::Cleanup_WFP_Filter();

			// Minifilter 해제
			EDR::MiniFilter::CleanUp_MiniFilter();

			// RegistryCallback 해제
			EDR::Registry::CleanUp_RegistryCallback();

			// ObRegisterCallback 해제
			EDR::ObRegisterCallback::CleanUp_ObRegisterCallbacks();

			// DLP
			DLP::CleanUp_DLP();

			return;
		}
	}
}