#ifndef LOGRECIEVER
#define LOGRECIEVER

#include "Util.hpp"

#include "IOCTL.hpp"
#include "EventLog.hpp"
#include "ProcessSession.hpp"
#include "NetworkSession.hpp"
#include "LogSender.hpp"
#include "EDR_C2C.hpp"

namespace EDR
{
	namespace LogReceiver
	{
		/*
			struct
		*/
		struct log_s
		{
			EDR::EventLog::Enum::EventLog_Enum Type;
			unsigned char* logData;
			ULONG64 logSize;
		};

		class LogManager
		{
			public:
				LogManager(EDR::Util::Kafka::Kafka& kafka, std::string arg_AGENT_ID) 
				: 
					kafka(kafka), 
					AGENT_ID(arg_AGENT_ID),
					WindowsLogSender(kafka, AGENT_ID),
					EDR_TCP(AGENT_ID, ioctl)
				{}
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
		};

	}
}


#endif
