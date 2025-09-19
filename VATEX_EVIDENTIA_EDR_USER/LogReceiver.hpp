#ifndef LOGRECIEVER
#define LOGRECIEVER

#include "Util.hpp"

#include "EventLog.hpp"
#include "ProcessSession.hpp"
#include "LogSender.hpp"

namespace EDR
{
	namespace LogReceiver
	{
		
		class Receiver
		{
			public:
				Receiver(EDR::Util::Kafka::Kafka& kafka, std::string AGENT_ID) : kafka(kafka), AGENT_ID(AGENT_ID), WindowsLogSender(kafka, AGENT_ID){}
				~Receiver(){
					if (is_ReceiveQueueWorking)
						is_ReceiveQueueWorking = false;
					if (is_APCLoopThreadHandle_loop)
						is_APCLoopThreadHandle_loop = false;
					if (APCLoopThreadHandle)
						CloseHandle(APCLoopThreadHandle);
				}

				BOOLEAN INITIALIZE(PHANDLE out_threadid, PVOID* APC_Handler);

			private:
				std::string AGENT_ID;


				// APC
				BOOLEAN is_APCLoopThreadHandle_loop = false;
				HANDLE APCLoopThreadHandle = NULL;


				EDR::Util::Kafka::Kafka& kafka;

				// queue 
				EDR::Util::Queue::Queue<EDR::EventLog::HandlerLog::HandlerLog_s> Queue;
				std::thread RecieveQueueThread;
				BOOLEAN is_ReceiveQueueWorking = false;

				/*
					Session
				*/
				EDR::Session::Process::ProcessSession ProcessSessionManager; // [橇肺技胶] 技记积己
				EDR::LogSender::Windows::LogSender WindowsLogSender; // [橇肺技胶] 技记积己
				

		};
	}
}


#endif
