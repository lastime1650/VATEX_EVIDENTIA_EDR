#include <iostream>
#include "Server/EDRServer.hpp"

#include <thread>   // std::this_thread::sleep_for
#include <chrono>   // std::chrono::seconds

int main()
{
    //test
    /*
    EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE sample("192.168.1.205");
    auto out = sample.Query_FILE_SHA256("08a25e1e926752f15b0e2fc79ce07ec41656b6fb55a3da4c0b579a8dc3face0e");

    for(const auto module : out->outputs)
        std::cout << "Module: " << module.ModuleName << " || " << module.output.value().dump() << std::endl;

    return 0;*/

    EDR::Server::EDRServer Server(
        /*
            Kafka Consume
        */
        "192.168.1.205:29092",
        "my_consumer_group5",
        "raw-edr-agent-windows",

        /*
            EDR Policy Arguments
        */
        "Policy/Association/rules",
        "Policy/Association/Scenario/rules",

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