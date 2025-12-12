#ifndef LOGRECIEVER
#define LOGRECIEVER

#include "Util.hpp"

#include "IOCTL.hpp"
#include "EventLog.hpp"
#include "ProcessSession.hpp"
#include "NetworkSession.hpp"
#include "LogSender.hpp"
#include "EDR_C2C.hpp"
#include "ETW_Management.hpp"

#include "LogReceiverShareStruct.hpp" // struct log_s

namespace EDR
{
	namespace LogReceiver
	{
		class LogManager
		{
			private:
				//#parallel_RecieveQueueThread;
				#define parallel_RecieveQueueThread_Count 6
				#define parallel_Kernel_RecieveQueueThread_Count 5
				std::vector<std::thread> parallel_RecieveLogDataThread; // by kernel
				std::vector<std::thread> parallel_RecieveQueueThread; // by kernel + user (ETW)
				std::vector< std::shared_ptr<EDR::Util::Queue::Queue<log_s>> > parallel_RecieveQueues;

			public:
				LogManager(EDR::Util::Kafka::Kafka& kafka, std::string arg_AGENT_ID) 
				: 
					kafka(kafka), 
					AGENT_ID(arg_AGENT_ID),
					WindowsLogSender(kafka, AGENT_ID),
					EDR_TCP(AGENT_ID, ioctl)
				{
					parallel_RecieveQueues.reserve(parallel_RecieveQueueThread_Count);
					for (int i = 0; i < parallel_RecieveQueueThread_Count; i++)
					{
						// emplace_back 措脚 push_back苞 make_unique 荤侩
						

						switch ((EDR::EventLog::Enum::QueueTypes)i)
						{
							case EDR::EventLog::Enum::QueueTypes::Queue_ProcessCreation:
							case EDR::EventLog::Enum::QueueTypes::Queue_ImageLoad:
							case EDR::EventLog::Enum::QueueTypes::Queue_Minifilter:
							case EDR::EventLog::Enum::QueueTypes::Queue_Registry:
							case EDR::EventLog::Enum::QueueTypes::Queue_WFP:
							case EDR::EventLog::Enum::QueueTypes::Queue_ETW:
							{
								parallel_RecieveQueues.push_back(std::make_shared<EDR::Util::Queue::Queue<log_s>>());
								break;
							}
						default:
							continue;
						}

					}
				}
				~LogManager() {
					Stop();
				}

				bool Run(std::string EDR_TCP_SERVER_IP, unsigned int EDR_TCP_SERVER_PORT);
				void Stop() {
					if (is_threading)
						is_threading = false;

					EDR_TCP.Stop();
				}

			private:
				EDR::IOCTL::Log_IOCTL ioctl;

				std::string AGENT_ID;
				std::string OS_VERSION;
				EDR::Util::Kafka::Kafka& kafka;

				
				std::thread RecieveLogDataThread;
				std::thread RecieveQueueThread;

				

				BOOLEAN is_threading = false;

				/*
					Session
				*/
				EDR::Session::Process::ProcessSession ProcessSessionManager; // [橇肺技胶] 技记积己
				EDR::Session::Network::NetworkSession NetworkSessionManager; // [匙飘况农] 技记积己

				EDR::LogSender::Windows::LogSender WindowsLogSender; // 肺弊 傈价 ( To Kafka )

				
				// queue 
				EDR::Util::Queue::Queue<log_s> Queue;


				// EDR TCP C2C
				EDR::C2C::EDRC2C EDR_TCP;

				// ETW MANAGER
				EDR::ETW::ETWManager ETW_Manager;
		};

	}
}

#endif