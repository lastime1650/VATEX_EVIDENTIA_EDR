#define _CRT_SECURE_NO_WARNINGS
#include <iostream>

#include "Util.hpp"

#include "LogReceiver.hpp"
#include "IOCTL.hpp"

#include "EventLog.hpp"


#include <cstdlib>

int main()
{
    /* ===== 환경변수 로딩 (main 바로 아래) ===== */

    const char* envKafkaIp = std::getenv("EDR_KAFKA_IP");
    const char* envKafkaPort = std::getenv("EDR_KAFKA_PORT");
    const char* envKafkaTopic = std::getenv("EDR_KAFKA_TOPIC");
    const char* envAgentIp = std::getenv("EDR_AGENT_IP");
    const char* envAgentPort = std::getenv("EDR_AGENT_PORT");

    std::string kafkaIp = envKafkaIp ? envKafkaIp : "192.168.1.200";
    int         kafkaPort = envKafkaPort ? std::atoi(envKafkaPort) : 29092;
    std::string kafkaTopic = envKafkaTopic ? envKafkaTopic : "raw-edr-agent-windows";

    std::string agentIp = envAgentIp ? envAgentIp : "192.168.1.200";
    int         agentPort = envAgentPort ? std::atoi(envAgentPort) : 6100;

    /* ===== 기존 로직 ===== */

    std::cout << kafkaIp << std::endl;

    std::string SMBIOS = EDR::Util::Windows::ReadSMBIOSType1And2();
    std::string AGENT_ID =
        EDR::Util::hash::sha256FromString(SMBIOS);

    std::cout << "AGENT_ID: " << AGENT_ID << std::endl;

    try {

        EDR::Util::Kafka::Kafka kafkaInstance(
            kafkaIp,
            kafkaPort,
            kafkaTopic
        );
        if (!kafkaInstance.Initialize())
        {
            std::runtime_error("Kafka Initialize Fail");
            return -1;
        }

        EDR::LogReceiver::LogManager logman(kafkaInstance, AGENT_ID);
        
        logman.Run(agentIp, agentPort);

    }
    catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return -1;
    }
    

    return 0;
}
