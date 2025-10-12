#ifndef AGENTTCP_HPP
#define AGENTTCP_HPP

#include "../../../util/util.hpp"



namespace EDR
{
    namespace Server
    {
        namespace AgentTcpManagement
        {

            namespace Enum
            {
                enum EDRC2C_ENUM
                {
                    RequestFileBin = 1,
                    RequestResponse_PROCESS,
                    RequestResponse_NETWORK,
                    RequestResponse_FILE
                };
            }

            class AgentTcp
            {
            public:
                AgentTcp(std::string ServerIp, unsigned int ServerPort) : tcpServer(ServerIp, ServerPort){
                    std::cout << "[AgentTcp]{Notice} AgentTcp created" << std::endl;
                }
                ~AgentTcp() { std::cout << "[AgentTcp]{Notice} ~AgentTcp called" << std::endl; Stop(); }

                bool Run()
                {
                    std::cout << "[AgentTcp]{Notice} Run() called" << std::endl;

                    is_working = tcpServer.OpenServer(  TcpClienthandler  );
                    if(!is_working)
                    {
                        std::cout << "[AgentTcp]{Failed} Run() -> tcpServer.OpenServer() Failed" << std::endl;
                        return false;
                    }

                    std::cout << "[AgentTcp]{Notice} Run() Running" << std::endl;
                    return true;
                }
                
                bool Stop()
                {
                    std::cout << "[AgentTcp]{Notice} AgentTcp.Stop() called" << std::endl;

                    if(!tcpServer.Close_Server())
                    {
                        std::cout << "[AgentTcp]{Failed} AgentTcp.Stop() -> tcpServer.Close_Server() Failed" << std::endl;
                        return false;
                    }

                    return true;
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
                bool Response_PROCESS(std::string AgentId, unsigned long long pid, std::string exe_path)
                {
                    /*
                        ```json
                        {
                            "agentid": "...",
                            "cmd" : Enum::RequestResponse_PROCESS ,
                            "parameter" :
                            {
                                "pid" : ....
                                "exe_path" : ...
                            }
                        }
                        ```
                    */
                    json result;
                    if ( !SendCommand(
                        AgentId,
                        {
                            {"agentid", AgentId},
                            {"cmd", (int)Enum::RequestResponse_PROCESS },
                            {"parameter",
                                {
                                    {"pid", pid},
                                    {"exe_path", exe_path.c_str()}
                                }
                            }
                        },
                        result
                        ) 
                    ) 
                        return false;

                    if( !result["result"].get<bool>() )
                        return false;

                    return true;
                }
                // 2-2. 파일 차단
                // 2-3. 네트워크 차단

                // Helper
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
                bool DisconnectAgent(std::string AgentId)
                {
                    auto it = Agent_ClientFd_Vec.find(AgentId);
                    if(it == Agent_ClientFd_Vec.end())
                        return false;
                    
                    auto ClientId = it->second;
                    tcpServer.Disconnect_Client(ClientId);

                    return true;
                }

            private:
                EDR::Util::Tcp::TcpServer tcpServer;
                bool is_working = false;

                // Tcp Client Handler
                // Tcp 에이전트 연결 검사
                std::function<void(int, std::string , int)> TcpClienthandler = 
                    [this](int clientfd, std::string client_ip, int client_port)
                    {
                        std::cout << "[TCP] " << " Clientfd: "<< clientfd << " IP/PORT: " << client_ip << ":" << client_port <<" connected" << std::endl;

                        std::vector<uint8_t> receiveBuffer;

                        // 1. get Initialize information from Agent
                        this->tcpServer.Receive(clientfd, receiveBuffer);
                        if(receiveBuffer.empty())
                        {
                            // 초기화 실패
                            std::cout <<"[AgentTcp]{FAILED} Handler INITIALIZE Failed" << std::endl;
                            this->tcpServer.Disconnect_Client(clientfd);
                            return;
                        }
                        std::cout << "received_data_size: " << receiveBuffer.size() << std::endl;

                        // to stirng
                        std::string InitJsonMessage(receiveBuffer.begin(), receiveBuffer.end());
                        if(InitJsonMessage.empty())
                        {
                            // 초기화 실패
                            std::cout <<"[AgentTcp]{FAILED} Handler INITIALIZE (vector to string) Failed" << std::endl;
                            this->tcpServer.Disconnect_Client(clientfd);
                            return;
                        }

                        // to json
                        json InitJson = json::parse(InitJsonMessage);
                        if(InitJson.empty())
                        {
                            // 초기화 실패
                            std::cout <<"[AgentTcp]{FAILED} Handler INITIALIZE (string to json) Failed" << std::endl;
                            this->tcpServer.Disconnect_Client(clientfd);
                            return;
                        }
                        

                        std::string Agent_Id;
                        try {
                            // 2. Get AGENTID
                            Agent_Id = InitJson["agentid"].get<std::string>();

                        } catch (const std::exception& e) {
                            std::cout <<"[AgentTcp]{FAILED} Handler INITIALIZE (json key error) Failed" << std::endl;
                            this->tcpServer.Disconnect_Client(clientfd);
                            return;
                        }
                        

                        /*
                            SUCCESS
                        */
                        Agent_ClientFd_Vec[Agent_Id] = clientfd;
                        std::cout <<"[AgentTcp]{Notice} Handler INITIALIZE Success" << std::endl;

                        // TEST
                        std::cout << "test: " << this->Response_PROCESS(
                            Agent_Id,
                            1234,
                            "C:\\test.exe"
                        ) << std::endl;
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