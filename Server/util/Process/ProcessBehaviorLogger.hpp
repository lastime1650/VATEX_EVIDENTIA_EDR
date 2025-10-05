#ifndef ProcessBehavior_HPP
#define ProcessBehavior_HPP

#include "../../../util/util.hpp"
#include "ProcessTree.hpp"


#include "../AgentTCP/AgentTcp.hpp"

#include "../Solution/_Manager/Policy/_Child/EDRPolicy.hpp" // EDR based Policy
#include "../Solution/_Manager/Manager.hpp" // Solution logics

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
                        std::string Kafkatopic
                    ) : KafkaConsumer( KafkaBroker, Kafkagroup_id, Kafkatopic ){}

                    ~ProcessBehaviorLogManager(){ Stop(); }

                    bool Run( Solution::Policy::EDRPolicy& EDRPolicyManager, EDR::Server::AgentTcpManagement::AgentTcp& AgentTCPManager, Solution::Intelligence::Intellina& IntelligenceManager )
                    {
                        is_working = true;


                        // Kafka 컨슈밍 스레드 생성
                        // Kafka Consuming Run
                        if(!KafkaConsumer.Run())
                            return false;



                        kafka_consuming_agent_log_thread = std::thread(
                            [this, &EDRPolicyManager, &AgentTCPManager, &IntelligenceManager]()
                            {
                                while(this->is_working)
                                {
                                    auto message = this->KafkaConsumer.get_message_from_queue();


                                    /*
                                        이벤트 별 전용 클래스(자식) 할당

                                        Log Json 키 기반 파싱

s
                                    */
                                   std::cout << message.original_message << std::endl;

                                    std::shared_ptr< EDR::Server::Util::ProcessEvent::Event > ev = nullptr; // 부모 
                                    if( message.message["body"].contains("network") )
                                    {
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::NetworkEvent >(message.message);

                                        /*
                                        
                                            << == Intelligence == >>

                                        */
                                        {
                                            // Source
                                            if(message.message["body"]["network"].contains("sourceip"))
                                            {
                                                // body/network/sourceip ip조회
                                                json output;

                                                // Only ip
                                                if( IntelligenceManager.Query_network_only_ipv4(
                                                    message.message["body"]["network"]["sourceip"].get<std::string>(),
                                                    output
                                                ) )
                                                    message.message["post"]["query_network_source_only_ipv4"] = output;
                                                
                                                if(message.message["body"]["network"].contains("sourceip"))
                                                {
                                                    // ip with port
                                                    if( IntelligenceManager.Query_network_ipv4_and_port(
                                                        message.message["body"]["network"]["sourceip"].get<std::string>(),
                                                        message.message["body"]["network"]["sourceport"].get<unsigned long long>(),
                                                        output
                                                    ) )
                                                        message.message["post"]["query_network_source_ipv4_and_port"] = output;
                                                }
                                                
                                            }

                                            // Destination
                                            if(message.message["body"]["network"].contains("destinationip"))
                                            {
                                                // body/network/destinationip ip조회
                                                json output;

                                                // Only ip
                                                if( IntelligenceManager.Query_network_only_ipv4(
                                                    message.message["body"]["network"]["destinationip"].get<std::string>(),
                                                    output
                                                ) )
                                                    message.message["post"]["query_network_dest_only_ipv4"] = output;

                                                if(message.message["body"]["network"].contains("destinationip"))
                                                {
                                                    // ip with port
                                                    if( IntelligenceManager.Query_network_ipv4_and_port(
                                                        message.message["body"]["network"]["destinationip"].get<std::string>(),
                                                        message.message["body"]["network"]["destinationport"].get<unsigned long long>(),
                                                        output
                                                    ) )
                                                        message.message["post"]["query_network_dest_ipv4_and_port"] = output;
                                                }

                                            }
                                        }
                                        
                                        
                                    }
                                    else if ( message.message["body"].contains("process") )
                                    {
                                        if ( message.message["body"]["process"]["action"].get<std::string>() == "create" )
                                        {
                                            /*
                                                프로세스 생성
                                            */
                                            ev = std::make_shared< EDR::Server::Util::ProcessEvent::ProcessCreateEvent >(message.message);

                                            {

                                                /*
                                        
                                                    << == Intelligence == >>

                                                */
                                                json output;
                                                // sha256
                                                if( IntelligenceManager.Query_file_sha256(
                                                    message.message["body"]["process"]["exe_sha256"].get<std::string>(),
                                                    output
                                                ) )
                                                    message.message["post"]["query_file_self_sha256"] = output;


                                                if( IntelligenceManager.Query_file_sha256(
                                                    message.message["body"]["process"]["parent_exe_sha256"].get<std::string>(),
                                                    output
                                                ) )
                                                    message.message["post"]["query_file_parent_sha256"] = output;
                                            }

                                        }
                                        else if ( message.message["body"]["process"]["action"].get<std::string>() == "remove" )
                                        {
                                            /*
                                                프로세스 종료
                                            */
                                            ev = std::make_shared< EDR::Server::Util::ProcessEvent::ProcessTerminateEvent >(message.message);
                                        }
                                    }
                                    else if ( message.message["body"].contains("filesystem") )
                                    {
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::FileSystemEvent >(message.message);

                                        {
                                            /*
                                        
                                                << == Intelligence == >>

                                            */
                                        }
                                    }
                                    else if (message.message["body"].contains("apicall") )
                                    {
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::API_Call_Event >(message.message);
                                    }

                                    /*
                                        Windows
                                    */
                                    else if ( message.message["body"].contains("imageload") )
                                    {
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::windows::ImageLoadEvent >(message.message);
                                    }
                                    else if ( message.message["body"].contains("processaccess") )
                                    {
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::windows::ProcessAccessEvent >(message.message);
                                    }
                                    else if (message.message["body"].contains("registry"))
                                    {
                                        ev = std::make_shared< EDR::Server::Util::ProcessEvent::windows::RegistryEvent >(message.message); 
                                    }
                                    /*
                                        Linux
                                    */
                                    /*...*/
                                    
                                    if(ev)
                                    {
                                        // Step1. 인텔리전스 + MITRE_ATTACK Mapping 매핑작업
                                        // Step2. Node 추가
                                        EDR::Server::Util::node::ProcessTreeNode* Mynode = nullptr;
                                        this->TreeManager.add_process_node(ev, Mynode);
                                        
                                        if(Mynode)
                                        {
                                            // 노드가 유효할 때, 후속 작업

                                            // Step3. event 개수 측정 
                                        }
                                    }
                                        
                                }
                            }
                        );
                    }
                    bool Stop()
                    {
                        {
                            if(!is_working)
                                return false;

                            if(!KafkaConsumer.Stop())
                                return false;

                            if(kafka_consuming_agent_log_thread.joinable())
                                kafka_consuming_agent_log_thread.join();
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

                    // node process tree manager
                    EDR::Server::Util::ProcessTreeManager TreeManager;
                    

            };
        }
    }
}

#endif