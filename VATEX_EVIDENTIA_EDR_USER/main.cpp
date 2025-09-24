#include <iostream>

#include "Util.hpp"

#include "LogReceiver.hpp"
#include "IOCTL.hpp"

#include "EventLog.hpp"

int main()
{
	
	std::string SMBIOS = EDR::Util::Windows::ReadSMBIOSType1And2();
	std::string AGENT_ID = // SHA256( SMBIOS Type 1+2 )
		EDR::Util::hash::sha256FromString(
			SMBIOS
		); 
	std::cout << "AGENT_ID: " << AGENT_ID << std::endl;
	
	EDR::Util::Kafka::Kafka kafkaInstance("192.168.1.205", 29092, "edr_agent_windows");
	if (!kafkaInstance.Initialize() )
	{
		std::runtime_error("Kafka Initialize Fail");
		return -1;
	}


	/*
		로그 수신부
	*/
	EDR::LogReceiver::LogManager logman(kafkaInstance, AGENT_ID);
	logman.Run();
		
	/*
		EDR 연결 부
	*/


	while(1){
		Sleep(INFINITE);
	}

	return 0;
}