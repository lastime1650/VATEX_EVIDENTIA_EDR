#include "LogReceiver.hpp"
#include "APC.hpp"

#include <iostream>
namespace EDR
{
	namespace LogReceiver
	{
		BOOLEAN Receiver::INITIALIZE(HANDLE* out_threadid, PVOID* APC_Handler)
		{
			APCLoopThreadHandle = EDR::APC::Init_APC(out_threadid, APC_Handler, &Queue);
			if (!APCLoopThreadHandle)
				return false;
			is_APCLoopThreadHandle_loop = true;

			is_ReceiveQueueWorking = true;
			RecieveQueueThread = std::thread(
				[this, Queue = &this->Queue, isWorking = &this->is_ReceiveQueueWorking]
				{
					std::cout << "RecieveQueueThread is running" << std::endl;
					while (*isWorking)
					{
						auto Log = Queue->get();

						/*
							RawData ( 로그 ) 캐스팅
						*/
						switch (Log.type)
						{
						case EDR::EventLog::Enum::Process_Create:
						{
							EDR::EventLog::Struct::Process::EventLog_Process_Create* ProcessCreatedLog = reinterpret_cast<EDR::EventLog::Struct::Process::EventLog_Process_Create*>(Log.logData);
							std::cout << "SID: " << ProcessCreatedLog->body.post.SID << std::endl;
							break;
						}
						case EDR::EventLog::Enum::Process_Terminate:
						{
							break;
						}
						case EDR::EventLog::Enum::ImageLoad:
						{
							break;
						}
						case EDR::EventLog::Enum::Network:
						{
							break;
						}
						case EDR::EventLog::Enum::Filesystem:
						{
							break;
						}
						case EDR::EventLog::Enum::ObRegisterCallback:
						{
							break;
						}
						default:
						{
							std::cout << "이해할 수 없는 로그" << std::endl;
							break;
						}
						}

						delete[] Log.logData;
					}
				}
			);
			return true;
		}
	}

}