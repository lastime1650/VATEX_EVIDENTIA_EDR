#ifndef ETW_MANAGER_HPP
#define ETW_MANAGER_HPP

#include <string>
#include <krabs.hpp>

#include "dotNet_Manager.hpp"

namespace EDR
{
	namespace ETW
	{
		class ETWManager
		{
		public:
			ETWManager(EDR::Util::Queue::IQueue& Queue, std::wstring TraceNameArg = L"Vatex_TRACER")
				: TraceName(TraceNameArg), ETW_tracer(TraceName), dotnet_manager(Queue)
			{}
			~ETWManager() {}

			bool SetupETWTraceByProviders()
			{

				if (!dotnet_manager.AddProviderToTrace(ETW_tracer))
				{
					std::wcerr << L"Failed to add .NET provider to ETW trace." << std::endl;
					return false;
				}

				return true;
			}

			bool StartETWTrace()
			{
				try
				{
					std::cout << "Starting..." << std::endl;
					ETW_tracer.start();
					return true;
				}
				catch (const std::exception& e)
				{
					std::cout << "Failed..." << std::endl;
					std::wcerr << L"Failed to start ETW trace: " << e.what() << std::endl;
					return false;
				}
			}

			bool StopETWTrace()
			{
				try
				{
					ETW_tracer.stop();
					return true;
				}
				catch (const std::exception& e)
				{
					std::wcerr << L"Failed to stop ETW trace: " << e.what() << std::endl;
					return false;
				}
			}

		private:
			std::wstring TraceName;
			krabs::user_trace ETW_tracer;


			// 1. Dotnet ±â¹Ý
			EDR::ETW::DOTNET::DotNetManager dotnet_manager;
		};
	}
}



#endif