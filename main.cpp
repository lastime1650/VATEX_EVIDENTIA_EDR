#include <iostream>
#include "Server/EDRServer.hpp"

#include <thread>   // std::this_thread::sleep_for
#include <chrono>   // std::chrono::seconds

int main()
{
    EDR::Server::EDRServer Server(
        /*
            Kafka Consume
        */
        "192.168.1.205:29092",
        "my_consumer_group2",
        "edr_agent_windows",

        /*
            EDR Policy Arguments
        */
        "",
        "",

        /*
            AgentTCP Server
        */
        "192.168.1.205",
        6100,

        /*
            VATEX EVIDENTIA EDR API Server
        */
        "192.168.1.205",
        51033,

        /*
            VATEX INTELLINA INTELLIGENCE API Connection
        */
       "192.168.1.205",
        51034
    );

    Server.Run();
    std::cout << "test" << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(9999));

    Server.Stop();

    return 0;
}