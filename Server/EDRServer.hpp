#ifndef EDRSERVER_HPP
#define EDRSERVER_HPP

#include "../util/util.hpp"
#include "util/Process/ProcessBehaviorLogger.hpp"

#include "util/ServerUtil.hpp"

namespace EDR
{
    namespace Server
    {
        class EDRServer
        {
            public:
                EDRServer(
                    std::string KafkaBroker,
                    std::string Kafkagroup_id,
                    std::string Kafkatopic,

                    std::string Mitre_Attack_rule_dir_path,
                    std::string Scenario_rule_dir_path,
                    

                    std::string EDR_AgentTCPServerIp,
                    unsigned int EDR_AgentTCPServerPort,

                    std::string EDR_APIServerIp,
                    unsigned int EDR_APIServerPort,

                    std::string VATEX_INTELLINA_API_ServerIp,
                    unsigned int VATEX_INTELLINA_API_ServerPort = 51034
                ) 
                : IntelligenceManager(VATEX_INTELLINA_API_ServerIp, VATEX_INTELLINA_API_ServerPort),
                BehaviorManager( KafkaBroker, Kafkagroup_id, Kafkatopic ),
                AgentTCPManager(EDR_AgentTCPServerIp, EDR_AgentTCPServerPort),
                PolicyManager(Mitre_Attack_rule_dir_path, Scenario_rule_dir_path)
                {
                    
                }   

                ~EDRServer(){ std::cout << "~EDRServer" << std::endl; Stop(); }

                // EDR 서버 Start
                bool Run()
                {
                    if(is_server_running)
                        std::runtime_error("EDR Server is already running ");
                    
                    // Step 0. [JSON기반 정책] PolicyManager
                    /* 필드&생성자 에 초기화되어 있음 */

                    // Step 1. [에이전트 간 TCP 통신]
                     if( !AgentTCPManager.Run() )
                        return false;

                    // Step 2. [에이전트 Kakfa기반 로그 관리 및 정책처리 ] Tree Behavior 수집 인스턴스 생성
                    if( !BehaviorManager.Run( PolicyManager, AgentTCPManager, IntelligenceManager ) )
                        return false;
                   

                    

                    // Plan: Web Server
                    // Plan: API Server
                    // Plan: SolutionManager (Solution Global Instance)
                    is_server_running = true;
                    
                }

                // EDR 서버 Stop
                bool Stop()
                {
                    if(!is_server_running)
                        std::runtime_error("EDR Server was stopped ");

                    //BehaviorManager.Stop();

                }



            private:

                // EDR서버 상태
                std::atomic<bool> is_server_running = false;

                /*
                    Features
                */
                

                // 프로세스 행위 트리 추적 매니저
                EDR::Server::ProcessBehavior::ProcessBehaviorLogManager BehaviorManager;

                // 에이전트 TCP
                EDR::Server::AgentTcpManagement::AgentTcp AgentTCPManager;

                // 탐지 정책
                Solution::Policy::EDRPolicy PolicyManager;

                // VATEX INTELLINA INTELLIGENCE API 호출 인스턴스
                Solution::Intelligence::Intellina IntelligenceManager;
                
        };

        /*
        // 보안솔루션 필수 기능 자식클래스
        namespace EDR_Solution_Management
        {
            using namespace Solution::Manager;

            template<typename test>
            class EDR_Solution_Manager : public Parent::SolutionManager
            {
                public:
                    EDR_Solution_Manager() : Parent::SolutionManager(){}

                protected:
                    bool Detection( const std::string& input, json& output ) override
                    {
                        
                            << 인자 정보 >>
                            1. input ( const json& input )
                                -> 
                            2. output  ( json& output )
                        
                       return true;
                    }

                    bool Request_Intelligence ( const json& input ) override
                    {
                        return true
                    }
                    bool Response( const json& input ) override
                    {
                        return true;
                    }
                    bool UnResponse( const json& input ) override
                    {
                        return true;
                    }
                    bool Get_Information( SolutionInfo::SolutionInfo_Parent& output ) override
                    {
                        return true;
                    }

            };
        }*/
        

    }
}

#endif