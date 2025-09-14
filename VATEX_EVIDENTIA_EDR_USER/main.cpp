#include "Util.hpp"

#include "LogReceiver.hpp"
#include "IOCTL.hpp"

int main()
{

	EDR::Util::Kafka::Kafka kafkaInstance("192.168.1.205", 29092, "edr_agent_windows");

	HANDLE APC_ThreadId = NULL;
	PVOID APC_Handler = NULL;
	EDR::LogReceiver::Receiver recevier(kafkaInstance);
	if (!recevier.INITIALIZE(&APC_ThreadId, &APC_Handler) || !APC_ThreadId)
		return -1;

	// IOCTL √ ±‚»≠
	EDR::IOCTL::IOCTL ioctl;
	if (!ioctl.INITIALIZE((HANDLE)GetCurrentProcessId(), APC_ThreadId, APC_Handler))
	{
		recevier.~Receiver();
		return -1;
	}


	system("pause");

	return 0;
}