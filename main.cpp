#include <iostream>
#include "Server/EDRServer.hpp"

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
        61010,

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

    if( !Server.Run() )
        return 0;
    std::cout << "test" << std::endl;
    while(1)
    {

    }

    Server.Stop();

    return 0;
}