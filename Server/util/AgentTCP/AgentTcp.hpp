#ifndef AGENTTCP_HPP
#define AGENTTCP_HPP

#include "../../../util/util.hpp"



namespace EDR
{
    namespace Server
    {
        namespace AgentTcpManagement
        {

            class AgentTcp
            {
            public:
                AgentTcp(std::string ServerIp, unsigned int ServerPort) : tcpServer(ServerIp, ServerPort){}

                bool Run()
                {
                    is_working = tcpServer.OpenServer(  TcpClienthandler  );
                    if(!is_working)
                        return false;
                }
                
                
                // 1. 바이너리 요청 ( BASE64 )
                bool Send_Command_Request_File( std::string AgentId, std::string filepath, std::vector<uint8_t>& binary )
                {
                    json result;
                    if ( !SendCommand(
                        AgentId,
                        json::parse(R"(
                            {{
                                "request": 
                                    {{
                                        "file" : 
                                            {{
                                                "path" : "{}"
                                            }}
                                    }}
                            }}
                        )", filepath.c_str()),
                        result
                    ) ) 
                        return false;
                    
                    // valid check
                    if( !result.contains("result") )
                        return false;
                    if( !result["result"].contains("base64") )
                        return false;
                    
                    std::string filebinary_base64( result["result"]["base64"].get<std::string>() );
                    if(filebinary_base64.empty())
                        return true; // 

                    std::string decoded = EDR::Util::Base64::base64_decode( filebinary_base64 );
                    
                    binary.insert( binary.end(), decoded.begin(), decoded.end() );

                    return true;
                }
                // 2. 차단 요청
                // 2-1. 프로세스 차단
                // 2-2. 파일 차단
                // 2-3. 네트워크 차단

                bool findClientfd_by_Agent(std::string AgentId, int& output)
                {
                    auto it = Agent_ClientFd_Vec.find(AgentId);
                    if(it == Agent_ClientFd_Vec.end())
                        return false;
                    
                    output = (it->second);
                    return true;
                }
                bool findAgent(std::string AgentId)
                {
                    auto it = Agent_ClientFd_Vec.find(AgentId);
                    if(it == Agent_ClientFd_Vec.end())
                        return false;

                    return true;
                }

            private:
                EDR::Util::Tcp::TcpServer tcpServer;
                bool is_working = false;

                // Tcp Client Handler
                std::function<void(int)> TcpClienthandler = 
                    [this](int clientfd)
                    {

                    };

                // Agent
                /*
                    key: AgentId
                    value: clientfd
                */
                std::map<std::string, int> Agent_ClientFd_Vec;


                // Agent에게 명령 전달
                bool SendCommand(std::string AgentId, json Data, json& output)
                {
                    int clientfd = -1;
                    if(!findClientfd_by_Agent(AgentId, clientfd))
                        return false;
                    
                    /*
                        << Input >>
                    */
                    std::string jsonString = Data.dump();  // json -> std::string
                    std::vector<uint8_t> vecdata(jsonString.begin(), jsonString.end());  // 바로 벡터 생성

                    if( !tcpServer.Send(clientfd, vecdata) )
                        return false;

                    /*
                        << Output >>
                    */
                    std::vector<uint8_t> out;
                    if( !tcpServer.Receive(clientfd, out) )
                        return false;
                    
                    std::string outString(out.begin(), out.end());
                    output = json::parse(outString);

                    return true;
                }
            };
        }
    }
}

#endif