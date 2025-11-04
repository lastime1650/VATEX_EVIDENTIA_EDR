#ifndef DOTNET_ETW_MANAGER_HPP
#define DOTNET_ETW_MANAGER_HPP

#include <string>
#include <krabs.hpp>

#include "callbacks.hpp"

namespace EDR
{
	namespace ETW
	{
		namespace DOTNET
		{
			class DotNetManager
			{
			public:
				DotNetManager(EDR::Util::Queue::IQueue& Queue)
					: DotNetCallbackcls(Queue),
					dotnet_provider(EDR::ETW::DOTNET::Providers::dotnet_runtime_t_provider_guid)
				{
					this->dotnet_provider.any(0xFFFFFFFFFFFFFFFF); // all subscriptions
					this->dotnet_provider.add_on_event_callback(DotNetCallbackcls.dotnet_event_callback);
				}
				~DotNetManager() {}

				bool AddProviderToTrace(krabs::user_trace& ETW_tracer)
				{
					try
					{
						ETW_tracer.enable(dotnet_provider);
						return true;
					}
					catch (const std::exception& e)
					{
						std::wcerr << L"Failed to enable .NET provider: " << e.what() << std::endl;
						return false;
					}
				}

			private:
				krabs::provider<> dotnet_provider;
				EDR::ETW::DOTNET::Callback::DotNetEventCallbackCls DotNetCallbackcls;
			};
		}
	}

}


#endif