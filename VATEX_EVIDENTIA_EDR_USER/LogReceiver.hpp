#ifndef LOGRECIEVER
#define LOGRECIEVER

#include "Util.hpp"

#include "EventLog.hpp"

namespace EDR
{
	namespace LogReceiver
	{
		
		class Receiver
		{
			public:
				Receiver(EDR::Util::Kafka::Kafka& kafka) : kafka(kafka) {}
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
				// APC
				BOOLEAN is_APCLoopThreadHandle_loop = false;
				HANDLE APCLoopThreadHandle = NULL;


				EDR::Util::Kafka::Kafka& kafka;

				// queue 
				EDR::Util::Queue::Queue<EDR::EventLog::HandlerLog::HandlerLog_s> Queue;
				std::thread RecieveQueueThread;
				BOOLEAN is_ReceiveQueueWorking = false;

		};
	}
}


#endif
