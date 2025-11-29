#ifndef LogReceiverShare_hpp
#define LogReceiverShare_hpp

#include "EventLog.hpp"
#include <Windows.h>
namespace EDR
{
	namespace LogReceiver
	{
		/*
			struct
		*/
		struct log_s
		{
			EDR::EventLog::Enum::EventLog_LogData_Type LogDataType;
			EDR::EventLog::Enum::EventLog_Enum Type;


			unsigned char* logData;
			ULONG64 logSize;
		};
	}
}


#endif