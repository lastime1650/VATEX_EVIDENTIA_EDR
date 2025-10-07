#include "edr/agent/starter.hpp"

#include <thread>   // std::this_thread::sleep_for
#include <chrono>   // std::chrono::seconds

int main()
{
    // AGENT ID -> Example -> a1d7216e7a22ffa61edbda0c87ee84cb56c8e06c82f28245e49b5cc36add1a6f
    std::string AGENT_ID( EDR::Util::Helper::hardware::Get_Hardware_hash() );
    if(AGENT_ID.empty())
        return -1;
    std::cout << "AGENT_ID: " << AGENT_ID << std::endl;


    EDR::Agent::EDRAgent agent(
        AGENT_ID,

        "192.168.1.205",
        29092,
        "edr_agent_linux"
    );
    agent.Run();
    
    std::this_thread::sleep_for(std::chrono::seconds(999999));
    return 0;
}