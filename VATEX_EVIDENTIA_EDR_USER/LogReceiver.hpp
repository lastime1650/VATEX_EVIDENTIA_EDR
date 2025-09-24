#ifndef LOGRECIEVER
#define LOGRECIEVER

#include "Util.hpp"

#include "IOCTL.hpp"
#include "EventLog.hpp"
#include "ProcessSession.hpp"
#include "LogSender.hpp"

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
				LogManager(EDR::Util::Kafka::Kafka& kafka, std::string AGENT_ID) : kafka(kafka), AGENT_ID(AGENT_ID), WindowsLogSender(kafka, AGENT_ID) {}
				~LogManager() {
					Stop();
				}

				bool Run();
				void Stop() {
					if (is_threading)
						is_threading = false;
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
				EDR::LogSender::Windows::LogSender WindowsLogSender; // [橇肺技胶] 技记积己

				
				// queue 
				EDR::Util::Queue::Queue<log_s> Queue;
		};

	}
}


#endif
