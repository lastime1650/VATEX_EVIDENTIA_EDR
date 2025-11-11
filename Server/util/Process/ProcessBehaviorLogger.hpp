#ifndef ProcessBehavior_HPP
#define ProcessBehavior_HPP

#include "../../../util/util.hpp"
#include "ProcessTree.hpp"


#include "../AgentTCP/AgentTcp.hpp"

#include "../Solution/_Manager/Policy/_Child/EDRPolicy.hpp" // EDR based Policy
#include "../Solution/_Manager/Manager.hpp" // Solution logics

#include <future>

namespace EDR
{
    namespace Server
    {
        namespace ProcessBehavior
        {
            class ProcessBehaviorLogManager
            {
                public:
                    ProcessBehaviorLogManager(
                        std::string KafkaBroker,
                        std::string Kafkagroup_id,
                        std::string Kafkatopic,

                        Solution::Policy::EDRPolicy& EDRPolicyManager,
                        EDR::Util::ToSiem::SiemClient& SiemClient,
                        Solution::AI::AI_MANAGER& AIManager
                    ) : 
                    KafkaConsumer( KafkaBroker, Kafkagroup_id, Kafkatopic ),
                    TreeManager(SiemClient, AIManager, EDRPolicyManager)
                    {
                        std::cout << "[ProcessBehaviorLogManager]{Notice} created" << std::endl;
                    }

                    ~ProcessBehaviorLogManager(){ std::cout << "[ProcessBehaviorLogManager]{Notice} ~ProcessBehaviorLogManager() called " << std::endl; Stop(); }

                    bool Run( EDR::Server::AgentTcpManagement::AgentTcp& AgentTCPManager, EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& IntelligenceManager )
                    {
                        is_working = true;
                        std::cout << "[ProcessBehaviorLogManager]{Notice} ProcessBehaviorLogManager.Run() called" << std::endl;


                        // Kafka 컨슈밍 스레드 생성
                        // Kafka Consuming Run
                        if(!KafkaConsumer.Run())
                        {
                            std::cout << "[ProcessBehaviorLogManager]{Failed} KafkaConsumer.Run() Failed" << std::endl;
                            return false;
                        }

                        kafka_consuming_agent_log_thread = std::thread(
                            [this, &AgentTCPManager, &IntelligenceManager]()
                            {
                                std::cout << "[ProcessBehaviorLogManager]{Notice} kafka_consuming_agent_log_thread Running" << std::endl;
                                while(this->is_working)
                                {
                                    auto message = this->KafkaConsumer.get_message_from_queue();

                                    //if(message.original_message.find("991b7a496ecaa7c4a3642c9243cd54073b4c5ad186dae9c2b88111e3e541a618") != std::string::npos)
                                        //std::cout << message.message.dump() << std::endl;

                                    //std::cout << "offest: " << message.offset << "message: " << message.message.dump() << std::endl;
                                    //std::cout << " ----- " << std::endl;
                                    
                                    /*
                                        이벤트 별 전용 클래스(자식) 할당

                                        Log Json 키 기반 파싱

s
                                    */
                                   

                                    std::shared_ptr< EDR::Server::Util::ProcessEvent::Event > ev = nullptr; // 부모 
                                    /*if( message.message["body"].contains("network") )
                                    {
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::NetworkEvent >(message.message, IntelligenceManager);
                                        
                                    }
                                    else*/ if ( message.message["body"].contains("process") )
                                    {
                                        if ( message.message["body"]["process"]["action"].get<std::string>() == "create" )
                                        {
                                            /*
                                                프로세스 생성
                                            */
                                            ev = std::make_shared< EDR::Server::Util::ProcessEvent::ProcessCreateEvent >(message.message, IntelligenceManager);

                                        }
                                        else if ( message.message["body"]["process"]["action"].get<std::string>() == "remove" )
                                        {
                                            /*
                                                프로세스 종료
                                            */
                                            ev = std::make_shared< EDR::Server::Util::ProcessEvent::ProcessTerminateEvent >(message.message, IntelligenceManager);
                                        }
                                    }
                                    /*else if ( message.message["body"].contains("filesystem") )
                                    {
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::FileSystemEvent >(message.message, IntelligenceManager);
                                    }
                                    else if (message.message["body"].contains("apicall") )
                                    {
                                        //std::cout << message.original_message << std::endl;
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::API_Call_Event >(message.message, IntelligenceManager);
                                    }

                                    
                                    //    Windows
                                    
                                    else if ( message.message["body"].contains("imageload") )
                                    {
                                        //std::cout << "offest: " << message.offset << "message: " << message.message.dump() << std::endl;
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::windows::ImageLoadEvent >(message.message, IntelligenceManager);
                                    }
                                    else if ( message.message["body"].contains("processaccess") )
                                    {
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::windows::ProcessAccessEvent >(message.message, IntelligenceManager);
                                    }
                                    else if (message.message["body"].contains("registry"))
                                    {
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::windows::RegistryEvent >(message.message, IntelligenceManager);
                                    }*/
                                    else if (message.message["body"].contains("etw"))
                                    {
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::windows::EtwEvent >(message.message, IntelligenceManager);
                                    }
                                    else
                                        // Unknown Event
                                        continue;
                                    /*
                                        Linux
                                    */
                                    /*...*/
                                    
                                    if(ev != nullptr)
                                    {
                                        // Step1. Node 추가
                                        //EDR::Server::Util::node::ProcessTreeNode* Mynode = nullptr;
                                        this->TreeManager.add_process_node(ev);
                                        
                                        //Node_Post_Processing_Asyncs.emplace_back(
                                        //     std::async(std::launch::async, [Mynode]() {
//
                                       //     })
                                        //);

                                        /*if(Mynode)
                                        {
                                            
                                            if(Mynode->session.Root_SessionID == "fa8b1139e95af25962b697c0cd841b0740102c854a3e40d02ec71e5357065993")
                                            {
                                                //std::string X = message.original_message + ",";
                                                //testFileHandle.writeToFile("./test.json", std::vector<uint8_t>(X.begin(), X.end()), true);
                                                std::cout << message.original_message <<"\n" << std::endl;
                                                

                                            }
                                            // Rule기반 탐지
                                            if( Mynode->AssociationRuleCTX )
                                                Mynode->AssociationRuleCTX->Match(ev->get_event()); // Match Postfix 작업은 내부에서 Action 됨 (자동화 Rule기반 보안알림 및 대응가능)

                                            // 인텔리전스 요청
                                            //.. ev에 포함된 메서드
                                            
                                        }*/
                                    }
                                        
                                }
                                std::cout << "[ProcessBehaviorLogManager]{Notice} kafka_consuming_agent_log_thread Stopped" << std::endl;
                            }
                        );
                        std::cout << "[ProcessBehaviorLogManager]{Notice} Running" << std::endl;
                        return true;
                    }
                    bool Stop()
                    {
                        {
                            std::cout << "[ProcessBehaviorLogManager]{Notice} ProcessBehaviorLogManager.Stop() called" << std::endl;

                            if(!is_working)
                            {
                                std::cout << "[ProcessBehaviorLogManager]{Failed} Stopping -> is_working !" << std::endl;
                                return false;
                            }
                                

                            if(!KafkaConsumer.Stop())
                            {
                                std::cout << "[ProcessBehaviorLogManager]{Failed} Stopping -> KafkaConsumer.Stop() Failed !" << std::endl;
                                return false;
                            }
                                
                            std::cout << "[ProcessBehaviorLogManager]{Notice} Stopping -> kafka_consuming_agent_log_thread joinable() waiting !" << std::endl;
                            if(kafka_consuming_agent_log_thread.joinable())
                                kafka_consuming_agent_log_thread.join();

                            std::cout << "[ProcessBehaviorLogManager]{Notice} Stopped" << std::endl;
                        }
                        
                        
                    }

                    bool SearchNode_by_AgentID(std::string AGENT_ID)
                    {

                    }

                private:

                    // AGENT -> EDR Kafka 컨슈머
                    EDR::Util::Kafka::Kafka_Consumer KafkaConsumer;

                    // Kafka로부터 로그 수신 스레드 관련 (모든 에이전트들의 로그를 수신)
                    std::atomic<bool> is_working = false;
                    std::thread kafka_consuming_agent_log_thread;


                    // node 타임아웃 스레드 관련 ( 타임아웃 발생시 노드 집중분석 진행 (후속분석: AI/ML 처리 , Sqlite저장) )
                    std::atomic<bool> is_working_timeout_node_thread = false;
                    std::thread node_timeout_thread;
                    void _node_timeout_thread()
                    {
                        while(is_working_timeout_node_thread)
                        {

                        }
                    }
                    EDR::Util::File::FileHandler testFileHandle;

                    // node process tree manager
                    EDR::Server::Util::ProcessTreeManager TreeManager;
                    

            };
        }
    }
}

#endif