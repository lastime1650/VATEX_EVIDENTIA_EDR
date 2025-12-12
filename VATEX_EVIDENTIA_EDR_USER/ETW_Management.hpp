#ifndef ETW_MANAGER_HPP
#define ETW_MANAGER_HPP

#include "Util.hpp"


#include <krabs.hpp>

#include "ETW_DotNet_Runtime.hpp"

#include "LogReceiverShareStruct.hpp" // struct log_s

namespace EDR
{
	namespace ETW
	{
		class ETWManager
		{
		public:
			~ETWManager() {}
			//bool _init(std::shared_ptr< EDR::Util::Queue::Queue<log_s> > Queue, std::wstring TraceNameArg = L"Vatex_TRACER")


			bool SetupETWTraceByProviders(std::shared_ptr< EDR::Util::Queue::Queue<EDR::LogReceiver::log_s> > Queue)
			{
				this->ETW_tracer = std::make_shared <  krabs::user_trace >(TraceName);
				if (!ETW_tracer)
					return false;


				// .NET ETW등록
				this->dotnet_manager = std::make_unique< EDR::ETW::DOTNET::DotNetManager >(Queue);
				if (!dotnet_manager)
					return false;

				


				// 1. .NET RUntime Event Trace
				if (!dotnet_manager->AddProviderToTrace(ETW_tracer))
				{
					std::wcerr << L"Failed to add .NET provider to ETW trace." << std::endl;
					return false;
				}

				return true;
			}

			bool StartETWTrace()
			{
				if (ETW_is_running)
					return false;

				ETW_is_running = true;
				ETW_Running_Thread = std::thread(
					[this]() 
					{
						try
						{
							std::cout << "Starting..." << std::endl;
							this->ETW_tracer->stop();
							this->ETW_tracer->start();
							std::cout << "ETW Shutdown" << std::endl;
						}
						catch (const std::exception& e)
						{
							std::cout << "Failed..." << std::endl;
							std::wcerr << L"Failed to start ETW trace: " << e.what() << std::endl;

							this->ETW_is_running = false;
							return;
						}
					}
				);
				ETW_Running_Thread.detach();
				std::cout << "StartETWTrace called" << std::endl; 
				return true;
			}

			bool StopETWTrace()
			{
				if (!ETW_is_running)
					return false;

				try
				{
					// ETW_tracer.stop()가 내부적으로 스레드 루프를 종료하도록 구현되어 있어야 함
					ETW_tracer->stop();

					// 스레드 종료를 기다리는 대신 플래그를 false로 바꿔 스레드 안에서 종료하게 유도
					ETW_is_running = false;

					return true;
				}
				catch (const std::exception& e)
				{
					std::wcerr << L"Failed to stop ETW trace: " << e.what() << std::endl;
					return false;
				}
			}

		
			


			bool ETW_is_running = false;
			std::wstring TraceName = L"Vatex_TRACER";
			std::shared_ptr <  krabs::user_trace > ETW_tracer;

		private:
			std::thread ETW_Running_Thread;

			// 1. Dotnet 기반
			std::unique_ptr< EDR::ETW::DOTNET::DotNetManager > dotnet_manager;
		};
	}
}



#endif