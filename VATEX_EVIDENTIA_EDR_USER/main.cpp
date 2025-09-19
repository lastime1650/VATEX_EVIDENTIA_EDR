#include <iostream>

#include "Util.hpp"

#include "LogReceiver.hpp"
#include "IOCTL.hpp"


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


	HANDLE APC_ThreadId = NULL;
	PVOID APC_Handler = NULL;
	EDR::LogReceiver::Receiver recevier(kafkaInstance, AGENT_ID);
	if (!recevier.INITIALIZE(&APC_ThreadId, &APC_Handler) || !APC_ThreadId)
		return -1;

	// IOCTL ÃÊ±âÈ­
	EDR::IOCTL::IOCTL ioctl;
	if (!ioctl.INITIALIZE((HANDLE)GetCurrentProcessId(), APC_ThreadId, APC_Handler))
	{
		recevier.~Receiver();
		return -1;
	}

	while(1){
		Sleep(INFINITE);
	}

	return 0;
}