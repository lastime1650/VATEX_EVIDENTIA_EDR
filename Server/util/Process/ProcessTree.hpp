#ifndef ProcessTree_HPP
#define ProcessTree_HPP

#include "../../../util/util.hpp"
#include "../Solution/_Manager/Manager.hpp" // Solution logics


namespace EDR
{
    namespace Server
    {
        namespace Util
        {
            namespace ProcessEvent
            {

                struct IntelligenceOutput
                {
                    EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE__RESPONSE intelligence_response;
                    std::string IntelligenceCategory; // e.g. network, file ,, 등
                };

                class Event
                {
                    public:
                        Event(json event, EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& Intelligence) : jsonEvent(event), Intelligence(Intelligence)
                        {
                            // 이벤트 공통 필드 저장
                            this->AGENT_ID = jsonEvent["header"]["agentid"].get<std::string>();
                            this->session.SessionID = jsonEvent["header"]["sessionid"].get<std::string>();
                            this->session.Root_SessionID = jsonEvent["header"]["root_sessionid"].get<std::string>();
                            this->session.Parent_SessionID = jsonEvent["header"]["parent_sessionid"].get<std::string>();
                            this->timestamp = jsonEvent["header"]["nano_timestamp"].get<unsigned long long>();
                            
                            if( jsonEvent["header"].contains("os") )
                            {
                                if( jsonEvent["header"]["os"].contains("type") )
                                    this->os.Platform = jsonEvent["header"]["os"]["type"].get<std::string>();
                                 if( jsonEvent["header"]["os"].contains("version") )
                                    this->os.Version = jsonEvent["header"]["os"]["version"].get<std::string>();
                            }
                            
                        }
                        virtual ~Event() = default;

                        json get_event(){ return jsonEvent; }
                        json get_header(){ return jsonEvent["header"]; }
                        json get_body(){ return jsonEvent["body"]; }


                        bool append_detected_rule()
                        {
                            return false;
                        }
                        
                        /*
                            Intelligence
                        */
                        virtual void send_to_intelligence() = 0;

                        // 인텔리전스 쿼리 결과 PUSH
                        bool append_intelligence( const std::string& category , const std::optional< EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE__RESPONSE >& response)
                        {
                            if(!response.has_value())
                                return false;
                            if( !response->is_success )
                                return false;

                            //std::cout << (response->outputs.begin()->second[0].output[0]) << std::endl;
                            intelligence_outputs.push_back( IntelligenceOutput{ 

                                    .intelligence_response = response.value(), 
                                    .IntelligenceCategory = category  
                                }  
                            );

                            return true;
                        }

                        // 지금까지 PUSHED 인텔리전스 쿼리 결과를 하나의 JSON으로 리턴
                        json output_intelligence_result_as_json()
                        {
                            auto Output = json::object();
                            Output["intelligence"] = json::array(); 

                            for(const auto& response : intelligence_outputs)
                            {
                                auto data = Intelligence.RESPONSE_to_Json(
                                    response.intelligence_response
                                );

                                if(data.has_value())
                                {
                                    Output["intelligence"].push_back(
                                        data.value()
                                    );
                                }
                            }

                            return Output;
                        }

                        std::vector<IntelligenceOutput>  output_intelligence_result_as_vector()
                        {
                            return intelligence_outputs;
                        }
                        

                        std::string AGENT_ID;
                        bool is_alive = true; // 노드 만료여부 
                        struct
                        {
                            std::string SessionID;
                            std::string Root_SessionID;
                            std::string Parent_SessionID;
                        }session;
                        
                        unsigned long long timestamp;

                        struct
                        {
                            std::string Platform;
                            std::string Version;
                        }os;
                        


                        EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& Intelligence;


                        

                        std::vector<IntelligenceOutput> intelligence_outputs;

                    protected:
                        json jsonEvent;

                        

                };

                class ProcessCreateEvent : public Event
                {
                    public:
                        ProcessCreateEvent(json event, EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& Intelligence) : Event(event, Intelligence) 
                        {
                            exe_path = event["body"]["process"]["exe_path"].get<std::string>();
                            if(exe_path.find("2d19.bat") != std::string::npos)
                            {
                                std::cout << ".bat 찾음" << std::endl;
                                std::cout << jsonEvent.dump() << std::endl;
                            }
                            exe_size = event["body"]["process"]["exe_size"].get<unsigned long long>();
                            exe_sha256 = event["body"]["process"]["exe_sha256"].get<std::string>();
                            commandline = event["body"]["process"]["commandline"].get<std::string>();
                            if(commandline.find("2d19.bat") != std::string::npos)
                            {
                                std::cout << ".bat 찾음" << std::endl;
                                std::cout << jsonEvent.dump() << std::endl;
                            }

                            ppid = event["body"]["process"]["ppid"].get<unsigned long long>();
                            parent_exe_path = event["body"]["process"]["parent_exe_path"].get<std::string>();
                            parent_exe_size = event["body"]["process"]["parent_exe_size"].get<unsigned long long>();
                            parent_exe_sha256 = event["body"]["process"]["parent_exe_sha256"].get<std::string>();

                            // User info
                            if ( event["body"]["user"].contains("sid") )
                            {
                                // Windows 기준
                                SID = event["body"]["user"]["sid"].get<std::string>();
                            }
                            
                            Username = event["body"]["user"]["username"].get<std::string>();
                            
                            if( exe_path.find("08a25e1e926752f15b0e2fc79ce07ec41656b6fb55a3da4c0b579a8dc3face0e") != std::string::npos )
                            {
                                std::cout << "[08a25e1e926752f15b0e2fc79ce07ec41656b6fb55a3da4c0b579a8dc3face0e] 찾음" << std::endl;
                                std::cout << event.dump() << std::endl;
                            }
                        }

                        std::string exe_path;
                        unsigned long long exe_size;
                        std::string exe_sha256;
                        std::string commandline;

                        unsigned long long ppid;
                        std::string parent_exe_path;
                        unsigned long long parent_exe_size;
                        std::string parent_exe_sha256;

                        std::optional< std::string > SID;
                        std::string Username;
                        

                        void send_to_intelligence() override
                        {
                            if( !exe_sha256.empty() )
                            {
                                append_intelligence(
                                    "file",
                                    Intelligence.Query_FILE_SHA256(exe_sha256)
                                );
                                    
                            }

                            if( parent_exe_sha256.length() )
                            {
                                append_intelligence(
                                    "file",
                                    Intelligence.Query_FILE_SHA256(parent_exe_sha256)
                                );
                            }

                        }
                        
                };
                class ProcessTerminateEvent : public Event
                {
                    public:
                        ProcessTerminateEvent(json event, EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& Intelligence) : Event(event, Intelligence) 
                        {
                            ppid = event["body"]["process"]["ppid"].get<unsigned long long>();
                        }

                        void send_to_intelligence()
                        {
                            throw std::runtime_error("ProcessTerminateEvent has no Intelligence override");
                        }
                        
                    unsigned long long ppid;
                };
                class FileSystemEvent : public Event
                {
                    public:
                        FileSystemEvent(json event, EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& Intelligence) : Event(event, Intelligence) 
                        {
                            action = event["body"]["filesystem"]["action"].get<std::string>();
                            filepath = event["body"]["filesystem"]["filepath"].get<std::string>();
                            filesize = event["body"]["filesystem"]["filesize"].get<unsigned long long>();
                            filesha256 = event["body"]["filesystem"]["filesha256"].get<std::string>();
                        }

                        void send_to_intelligence() override
                        {
                            if( filesha256.length() >= 64 )
                            {
                                append_intelligence(
                                    "file",
                                    Intelligence.Query_FILE_SHA256(filesha256)
                                );
                            }

                        }

                        std::string action;
                        
                        std::string filepath;
                        unsigned long long filesize;
                        std::string filesha256;
                };
                class NetworkEvent : public Event
                {
                    public:
                        NetworkEvent(json event, EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& Intelligence) : Event(event, Intelligence) 
                        {
                            interface_index = event["body"]["network"]["interface_index"].get<unsigned int>();
                            protocol = event["body"]["network"]["protocol"].get<std::string>();
                            packetsize = event["body"]["network"]["packetsize"].get<unsigned int>();

                            sourceip = event["body"]["network"]["sourceip"].get<std::string>();
                            sourceport = event["body"]["network"]["sourceport"].get<unsigned int>();
                            destinationip = event["body"]["network"]["destinationip"].get<std::string>();
                            destinationport =  event["body"]["network"]["destinationport"].get<unsigned int>();

                            direction = event["body"]["network"]["direction"].get<std::string>();

                            network_sessionid = event["body"]["network"]["session"]["sessionid"].get<std::string>();
                            network_first_seen = event["body"]["network"]["session"]["first_seen"].get<unsigned long long>();
                            network_last_seen = event["body"]["network"]["session"]["last_seen"].get<unsigned long long>();
                        }

                        void send_to_intelligence() override
                        {

                            
                            if(direction == "out")
                            {
                                // target - destination
                                
                                /*
                                    destination
                                */
                                if(destinationip.length())
                                {
                                    append_intelligence(
                                        "network",
                                        Intelligence.Query_NETWORK_IPV4(destinationip)
                                    );
                                    
                                    if(destinationport)
                                    {
                                        append_intelligence(
                                            "network",
                                            Intelligence.Query_NETWORK_IPV4_with_PORT(destinationip, destinationport)
                                        );
                                    }
                                }
                                
                            }
                            else if(direction == "in")
                            {
                                // target - source

                                /*
                                    Source
                                */
                                if(sourceip.length())
                                {
                                    append_intelligence(
                                        "network",
                                        Intelligence.Query_NETWORK_IPV4(sourceip)
                                    );
                                    
                                    if(sourceport)
                                    {
                                        append_intelligence(
                                            "network",
                                            Intelligence.Query_NETWORK_IPV4_with_PORT(sourceip, sourceport)
                                        );
                                    }
                                }
                            }
                            

                        }

                    private:
                        unsigned int interface_index;
                        std::string protocol;
                        unsigned int packetsize;
                        std::string sourceip;
                        unsigned int sourceport;
                        std::string destinationip;
                        unsigned int destinationport;
                        std::string direction;

                        std::string network_sessionid;
                        unsigned long long network_first_seen;
                        unsigned long long network_last_seen;
                };

                class API_Call_Event : public Event
                {
                    public:
                        API_Call_Event(json event, EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& Intelligence) : Event(event, Intelligence) 
                        {
                            APIName = event["body"]["apicall"]["function"].get<std::string>();

                            if( event["body"]["apicall"].contains("args") )
                            {
                                Args = event["body"]["apicall"]["args"].get<std::vector<std::string>>();
                            }

                            if( event["body"]["apicall"].contains("return") )
                            {
                                ReturnValue = event["body"]["apicall"]["return"].get<std::string>();
                            }
                        }
                        void send_to_intelligence() override
                        {
                            throw std::runtime_error("API CALL has no intelligence");

                        }
                    private:
                        std::string APIName;
                        std::vector< std::string > Args;
                        std::string ReturnValue;
                };
                
                namespace windows
                {
                    class ImageLoadEvent : public Event
                    {
                        public:
                            ImageLoadEvent(json event, EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& Intelligence) : Event(event, Intelligence) 
                            {
                                filepath = event["body"]["imageload"]["filepath"].get<std::string>();
                                filesize = event["body"]["imageload"]["filesize"].get<unsigned long long>();
                                filesha256 = event["body"]["imageload"]["filesha256"].get<std::string>();
                            }
                            void send_to_intelligence() override
                            {
                                if( filesha256.length() >= 64 )
                                {
                                    append_intelligence(
                                        "file",
                                        Intelligence.Query_FILE_SHA256(filesha256)
                                    );
                                }

                            }
                        private:
                            std::string filepath;
                            unsigned long long filesize;
                            std::string filesha256;
                    };

                    class ProcessAccessEvent : public Event
                    {
                        public:
                            ProcessAccessEvent(json event, EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& Intelligence) : Event(event, Intelligence) 
                            {
                                handletype = event["body"]["processaccess"]["handletype"].get<std::string>();
                                filepath = event["body"]["processaccess"]["filepath"].get<std::string>();
                                target_pid = event["body"]["processaccess"]["target_pid"].get<unsigned long long>();
                                desiredaccesses = event["body"]["processaccess"]["desiredaccesses"].get<std::vector<std::string>>();
                            }
                            void send_to_intelligence() override
                            {
                                throw std::runtime_error("ProcessAccessEvent has no intelligence");

                            }

                        private:
                            std::string handletype;
                            
                            unsigned long long target_pid;
                            std::string filepath;
                            std::vector< std::string > desiredaccesses;
                    };

                    class RegistryEvent : public Event
                    {
                        public:
                            RegistryEvent(json event, EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& Intelligence) : Event(event, Intelligence) 
                            {
                                KeyClass = event["body"]["registry"]["keyclass"].get<std::string>();
                                Object_Complete_Name = event["body"]["registry"]["name"].get<std::string>();
                                if( event["body"]["registry"].contains("newold") )
                                {
                                    newold.is_valid = true;
                                    newold.OldName = event["body"]["registry"]["newold"]["oldname"];
                                    newold.NewName = event["body"]["registry"]["newold"]["newname"];
                                }
                            }
                            void send_to_intelligence() override
                            {
                                throw std::runtime_error("RegistryEvent has no intelligence");

                            }

                        private:
                            std::string KeyClass;
                            std::string Object_Complete_Name;

                            struct NewOld
                            {
                                bool is_valid = false;
                                std::string OldName;
                                std::string NewName;
                            };
                            struct NewOld newold;
                    };


                    class EtwEvent : public Event
                    {
                        public:
                            EtwEvent(json event, EDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& Intelligence) : Event(event, Intelligence) 
                            {
                                provider_name = event["body"]["etw"]["provider_name"].get<std::string>();
                                event_name = event["body"]["etw"]["event_name"].get<std::string>();
                                event_id = event["body"]["etw"]["event_id"].get<unsigned int>();
                                event_flags = event["body"]["etw"]["event_flags"].get<unsigned int>();
                                event_version = event["body"]["etw"]["event_version"].get<unsigned int>();

                                if( event_name == "LoaderModuleLoad_V2" )
                                    std::cout << jsonEvent.dump()  << std::endl;

                                // fields
                                for( const auto& [key, value] : event["body"]["etw"]["fields"].items())
                                {
                                    fields.push_back(
                                        ETW_FIELDS{
                                            .FieldName = key,
                                            .FieldValue = value
                                        }
                                    );
                                }

                            }
                            void send_to_intelligence() override
                            {
                                throw std::runtime_error("ETW has no intelligence");

                            }

                        private:
                            std::string provider_name;
                            std::string event_name;
                            unsigned int event_id;
                            unsigned int event_flags;
                            unsigned int event_version;
                            


                            struct ETW_FIELDS
                            {
                                std::string FieldName;
                                std::string FieldValue;
                            };
                            std::vector<ETW_FIELDS> fields;

                            
                    };


                    
                }
                namespace linux
                {

                }
            }

            namespace node
            {
                // 노드가 종료된 이유를 나타내는 열거형
                enum class TerminateReason
                {
                    NONE,                       // 아직 종료되지 않음
                    BY_EVENT,                   // 정상적인 종료 이벤트 수신
                    BY_MAX_EVENTS_LIMIT,        // 노드 내 최대 이벤트 수 초과
                    BY_MAX_NODES_LIMIT,         // 트리 내 최대 자식 노드 수 초과 (루트 노드에만 설정됨)
                    BY_TIMEOUT                  // 장시간 활동이 없어 타임아웃 처리
                };

                // 루트 노드에 의해 공유될 타임스탬프 구조체
                struct ProcessTreeTimestamp
                {
                    std::atomic<unsigned long long> first_seen{0};
                    std::atomic<unsigned long long> last_seen{0};
                };

                // 프로세스 트리의 각 노드를 나타내는 구조체
                struct ProcessTreeNode
                {

                    // 세션 busy 체크 ( 부모에서 최초 shared_ptr 생성 되고, 자식은 참조만 . )
                    std::shared_ptr<std::atomic<unsigned long long>> busy_ref_count;

                    // --- 고유 정보 ---
                    std::string AGENT_ID;
                    struct {
                        std::string SessionID;
                        std::string Root_SessionID;
                        std::string Parent_SessionID;
                    } session;
                    unsigned long long nodeDepthIndex = 0;

                    // --- 상태 정보 ---
                    std::atomic<bool> is_alive{true};
                    std::atomic<bool> is_placeholder{true};
                    TerminateReason termination_reason = TerminateReason::NONE;
                    
                    // --- 이벤트 및 자식 노드 ---
                    std::vector<std::shared_ptr<ProcessEvent::Event>> events;
                    std::vector<std::shared_ptr<ProcessTreeNode>> Child;

                    

                    // --- 타임스탬프 ---
                    // 이 노드 자체의 이벤트 기반 타임스탬프
                    struct {
                        unsigned long long first_seen = 0;
                        unsigned long long last_seen = 0;
                    } seen_by_event;
                    
                    // 트리 전체의 활동을 추적하기 위해 루트 노드에서 생성되고 공유되는 타임스탬프
                    std::shared_ptr<ProcessTreeTimestamp> shared_tree_timestamp;

                    // --- 분석 및 정책 또는 AI 샘플링 관련 ---
                    std::shared_ptr<Solution::Policy::Resource::Association::ASSOCIATION_RULE_MANAGER> AssociationRuleCTX = nullptr;
                    std::vector<Solution::Policy::Resource::Association::Global::AssociationRuleStruct::Header> MatchedRules;// 룰 탐지 결과 리스트

                    //std::atomic<float> threat_score{0.0f};
                    //std::atomic<bool> analysis_submitted{false};
                    
                    // --- 헬퍼 함수들 (포인터 기반으로 수정됨) ---
                    bool append_matched_rule(std::vector<Solution::Policy::Resource::Association::RuleMatchedOutput>& args_matchedRules)
                    {
                        if(args_matchedRules.empty())
                            return false;

                        // key가 "rule"인 룰 전용 event를 생성하고, MatchedRules 필드에 push_back진행
                        for (auto& rule : args_matchedRules)
                            MatchedRules.push_back( rule.RuleInfo );

                        return true;
                    }

                    // 모든 하위 자식들이 종료되었는지 재귀적으로 확인
                    bool are_all_children_terminated() const
                    {
                        for (const auto& child_ptr : Child)
                        {
                            if (child_ptr->is_alive || !child_ptr->are_all_children_terminated())
                            {
                                return false;
                            }
                        }
                        return true;
                    }

                    // 모든 자식 노드의 개수를 재귀적으로 계산
                    unsigned int get_all_child_count()
                    {
                        unsigned int count = 0;
                        for (const auto& child_ptr : Child)
                        {
                            count += 1 + child_ptr->get_all_child_count();
                        }
                        return count;
                    }

                    // 현재 노드부터 모든 하위 노드의 이벤트를 시간순으로 정렬하여 반환
                    std::vector<json> get_all_events_sorted_by_time()
                    {
                        std::vector<std::shared_ptr<ProcessEvent::Event>> all_events;
                        std::function<void(const ProcessTreeNode&)> collect_events =
                            [&](const ProcessTreeNode& node) {
                                all_events.insert(all_events.end(), node.events.begin(), node.events.end());
                                for (const auto& child : node.Child) {
                                    collect_events(*child);
                                }
                            };
                        collect_events(*this);

                        std::sort(all_events.begin(), all_events.end(),
                            [](const auto& a, const auto& b) {
                                return a->timestamp < b->timestamp;
                            });

                        std::vector<json> sorted_json_events;
                        for (const auto& ev_ptr : all_events) {
                            if(ev_ptr) sorted_json_events.push_back(ev_ptr->get_event());
                        }
                        return sorted_json_events;
                    }

                    // 현재 노드와 하위 트리를 JSON으로 변환
                    bool to_jsonTree(json& output)
                    {
                        try {
                            // --- 1. 기본 노드 정보 직렬화 (기존과 동일) ---
                            output = {
                                {"AGENT_ID", AGENT_ID},
                                {"is_alive", is_alive.load()},
                                {"is_placeholder", is_placeholder.load()},
                                {"nodeDepthIndex", nodeDepthIndex},
                                {"child_count", get_all_child_count()},
                                {"session", {
                                    {"SessionID", session.SessionID},
                                    {"Root_SessionID", session.Root_SessionID},
                                    {"Parent_SessionID", session.Parent_SessionID}
                                }}
                            };
                            // 타임스탬프 정보도 추가하면 유용합니다.
                            if (shared_tree_timestamp) {
                                output["shared_tree_timestamp"] = {
                                    {"first_seen", shared_tree_timestamp->first_seen.load()},
                                    {"last_seen", shared_tree_timestamp->last_seen.load()}
                                };
                            }

                            // --- 2. 'events' 필드 채우기 (수정된 부분) ---
                            output["events"] = get_all_events_sorted_by_time();

                            return true;
                        } catch (const std::exception& e) {
                            std::cerr << "to_jsonTree failed for SessionID " << session.SessionID << ": " << e.what() << std::endl;
                            return false;
                        }
                    }
                };
            } // namespace node

            // 에이전트별 프로세스 트리를 관리하는 구조체 (세분화된 잠금을 위함)
            struct AgentProcessTree
            {
                std::mutex mtx;
                std::vector<std::shared_ptr<node::ProcessTreeNode>> root_nodes;

                AgentProcessTree() = default;
                AgentProcessTree(const AgentProcessTree&) = delete;
                AgentProcessTree& operator=(const AgentProcessTree&) = delete;
                AgentProcessTree(AgentProcessTree&&) = default;
                AgentProcessTree& operator=(AgentProcessTree&&) = default;
            };

            // --- 메인 트리 관리 클래스 ---
            class ProcessTreeManager
            {
            public:
                ProcessTreeManager(
                    EDR::Util::ToSiem::SiemClient& SiemClient,
                    Solution::Policy::EDRPolicy& EDRPolicyManager,
                    size_t max_events_per_node = 5000,
                    size_t max_nodes_per_tree = 1000,
                    size_t MAX_ASYNC_TASKS = 10000,
                    unsigned long long tree_timeout_ms = 300000 // 5분
                ) : SiemClient(SiemClient),
                    EDRPolicyManager(EDRPolicyManager),
                    MAX_EVENTS_PER_NODE(max_events_per_node),
                    MAX_NODES_PER_TREE(max_nodes_per_tree),
                    MAX_ASYNC_TASKS(MAX_ASYNC_TASKS),
                    TREE_TIMEOUT_MS(tree_timeout_ms)
                {
                    is_TreeManager_Running = true;
                    TreeCleanUpLoopThread = std::thread(&ProcessTreeManager::TreeCleanUpLoopThread_Function, this);
                    TreeAsyncCleanUpLoopThread = std::thread(&ProcessTreeManager::TreeAsyncCleanUpLoopThreat_Function, this);
                    TreeCompletedProcessingThread = std::thread(&ProcessTreeManager::TreeCompletedProcessingThreadRoutine, this);
                }

                ~ProcessTreeManager()
                {
                    is_TreeManager_Running = false;
                    if (TreeCleanUpLoopThread.joinable())
                    {
                        TreeCleanUpLoopThread.join();
                    }
                    if (TreeAsyncCleanUpLoopThread.joinable())
                    {
                        TreeAsyncCleanUpLoopThread.join();
                    }
                    if (TreeCompletedProcessingThread.joinable())
                    {
                        TreeCompletedProcessingThread.join();
                    }
                }

                bool add_process_node(std::shared_ptr<ProcessEvent::Event> eventNode)
                {
                    // 1. AgentProcessTree 포인터 가져오기 (없으면 생성)
                    std::shared_ptr<AgentProcessTree> agent_tree_ptr;
                    {
                        std::lock_guard<std::mutex> map_lock(map_mutex);
                        auto it = tree_map.find(eventNode->AGENT_ID);
                        if (it == tree_map.end()) {
                            it = tree_map.emplace(eventNode->AGENT_ID, std::make_shared<AgentProcessTree>()).first;
                        }
                        agent_tree_ptr = it->second;
                    }

                    std::shared_ptr<node::ProcessTreeNode> node_for_async = nullptr;

                    // 2. 해당 에이전트의 트리만 잠그고 작업 수행
                    std::lock_guard<std::mutex> lock(agent_tree_ptr->mtx);
                    auto& agent_root_nodes = agent_tree_ptr->root_nodes;

                    auto target_node_ptr = _find_node_by_session_id(agent_root_nodes, eventNode->session.SessionID);

                    // --- 시나리오 1: 노드가 아직 존재하지 않음 ---
                    if (!target_node_ptr)
                    {
                        auto root_node_ptr = _find_node_by_session_id(agent_root_nodes, eventNode->session.Root_SessionID);
                        if (root_node_ptr && root_node_ptr->get_all_child_count() >= MAX_NODES_PER_TREE)
                        {
                            if (root_node_ptr->is_alive) {
                                root_node_ptr->is_alive = false;
                                root_node_ptr->termination_reason = node::TerminateReason::BY_MAX_NODES_LIMIT;
                            }
                            //node_output = nullptr;
                            return false; // 자식 생성 거부
                        }

                        auto new_node_ptr = std::make_shared<node::ProcessTreeNode>();
                        new_node_ptr->AGENT_ID = eventNode->AGENT_ID;
                        new_node_ptr->session.Root_SessionID = eventNode->session.Root_SessionID;
                        new_node_ptr->session.Parent_SessionID = eventNode->session.Parent_SessionID;
                        new_node_ptr->session.SessionID = eventNode->session.SessionID;
                        new_node_ptr->seen_by_event.first_seen = eventNode->timestamp;
                        new_node_ptr->seen_by_event.last_seen = eventNode->timestamp;
                        new_node_ptr->events.push_back(eventNode);

                        if (new_node_ptr->session.SessionID == new_node_ptr->session.Root_SessionID) { // 루트 노드인 경우
                            new_node_ptr->AssociationRuleCTX = EDRPolicyManager.Get_Cloned_AssociationRuleCTX();
                            new_node_ptr->shared_tree_timestamp = std::make_shared<node::ProcessTreeTimestamp>();
                            unsigned long long now = EDR::Util::timestamp::Get_Real_Timestamp();
                            new_node_ptr->shared_tree_timestamp->first_seen = now;
                            new_node_ptr->shared_tree_timestamp->last_seen = now;

                            new_node_ptr->busy_ref_count = std::make_shared<std::atomic<unsigned long long>>(0);
                        } else {
                            if (root_node_ptr) {
                                new_node_ptr->AssociationRuleCTX = root_node_ptr->AssociationRuleCTX;
                                new_node_ptr->shared_tree_timestamp = root_node_ptr->shared_tree_timestamp;
                                new_node_ptr->busy_ref_count = root_node_ptr->busy_ref_count;
                            }
                        }

                        if (new_node_ptr->shared_tree_timestamp) {
                            new_node_ptr->shared_tree_timestamp->last_seen = EDR::Util::timestamp::Get_Real_Timestamp();
                        }

                        if (dynamic_cast<ProcessEvent::ProcessCreateEvent*>(eventNode.get())) {
                            new_node_ptr->is_placeholder = false;
                        }
                        if (dynamic_cast<ProcessEvent::ProcessTerminateEvent*>(eventNode.get())) {
                            new_node_ptr->is_alive = false;
                            new_node_ptr->termination_reason = node::TerminateReason::BY_EVENT;
                        }

                        _place_new_node(agent_root_nodes, new_node_ptr);
                        //node_output = new_node_ptr;

                        
                        node_for_async = new_node_ptr;// async 인수로 활용
                    }
                    // --- 시나리오 2: 노드가 이미 존재함 ---
                    else
                    {
                        if (!target_node_ptr->is_alive) { // 이미 종료된 노드에는 이벤트 추가 안 함
                            //node_output = target_node_ptr;
                            return false;
                        }
                        
                        if (target_node_ptr->events.size() >= MAX_EVENTS_PER_NODE) {
                            target_node_ptr->is_alive = false;
                            target_node_ptr->termination_reason = node::TerminateReason::BY_MAX_EVENTS_LIMIT;
                            //node_output = target_node_ptr;
                            return false; // 새 이벤트 추가 거부
                        }

                        target_node_ptr->events.push_back(eventNode);
                        target_node_ptr->seen_by_event.last_seen = std::max(target_node_ptr->seen_by_event.last_seen, eventNode->timestamp);
                        
                        if (target_node_ptr->shared_tree_timestamp) {
                            target_node_ptr->shared_tree_timestamp->last_seen = EDR::Util::timestamp::Get_Real_Timestamp();
                        }

                        if (target_node_ptr->is_placeholder && dynamic_cast<ProcessEvent::ProcessCreateEvent*>(eventNode.get())) {
                            target_node_ptr->is_placeholder = false;
                            std::rotate(target_node_ptr->events.rbegin(), target_node_ptr->events.rbegin() + 1, target_node_ptr->events.rend());
                        }

                        if (dynamic_cast<ProcessEvent::ProcessTerminateEvent*>(eventNode.get())) {
                            target_node_ptr->is_alive = false;
                            target_node_ptr->termination_reason = node::TerminateReason::BY_EVENT;
                        }
                        //node_output = target_node_ptr;


                        //auto root_node_ptr = _find_node_by_session_id(agent_root_nodes, eventNode->session.Root_SessionID);
                        //if(root_node_ptr && !root_node_ptr->is_placeholder && root_node_ptr->get_all_child_count() >= 1)
                        //{
                        //    json tree;
                            //if( root_node_ptr->to_jsonTree(tree) )
                                //std::cout << tree.dump() << std::endl;
                        //}

                        node_for_async = target_node_ptr;
                    }


                    _Async_Tree_Processing(eventNode, node_for_async);

                    return true;
                }

                // 완료된 트리 데이터를 가져갈 수 있는 큐 인터페이스
                //std::optional<json> get_completed_tree_from_queue() {
                //    return CompleteProcessNodeTreeQueue.pop();
               // }

            private:
                EDR::Util::ToSiem::SiemClient& SiemClient;
                Solution::Policy::EDRPolicy& EDRPolicyManager;
                const size_t MAX_EVENTS_PER_NODE;
                const size_t MAX_NODES_PER_TREE;
                const size_t MAX_ASYNC_TASKS;
                const unsigned long long TREE_TIMEOUT_MS;

                using TreeMap = std::map<std::string, std::shared_ptr<AgentProcessTree>>;
                TreeMap tree_map;
                std::mutex map_mutex; // TreeMap 자체를 보호하기 위한 뮤텍스

                EDR::Util::Queue::Queue<json> CompleteProcessNodeTreeQueue;

                // --- Async 후속 작업 ---
                std::vector< std::future<void> > Async_Tree_Processing_asyncs;
                std::mutex Async_Mutex;

                // --- 백그라운드 스레드 관련 ---
                std::atomic<bool> is_TreeManager_Running{false};
                std::thread TreeCleanUpLoopThread;
                std::thread TreeAsyncCleanUpLoopThread;
                std::thread TreeCompletedProcessingThread;

                // --- 내부 헬퍼 함수 (모두 포인터 기반) ---

                std::shared_ptr<node::ProcessTreeNode> _find_node_by_session_id(std::vector<std::shared_ptr<node::ProcessTreeNode>>& nodes, const std::string& session_id)
                {
                    for (auto& node_ptr : nodes) {
                        if (node_ptr->session.SessionID == session_id) return node_ptr;
                        if (auto found = _find_node_by_session_id(node_ptr->Child, session_id)) return found;
                    }
                    return nullptr;
                }

                void _place_new_node(std::vector<std::shared_ptr<node::ProcessTreeNode>>& agent_tree, std::shared_ptr<node::ProcessTreeNode> new_node_ptr)
                {
                    if (new_node_ptr->session.SessionID == new_node_ptr->session.Root_SessionID) {
                        new_node_ptr->nodeDepthIndex = 0;
                        agent_tree.push_back(new_node_ptr);
                        return;
                    }
                    auto parent_node_ptr = _find_node_by_session_id(agent_tree, new_node_ptr->session.Parent_SessionID);
                    if (parent_node_ptr) {
                        new_node_ptr->nodeDepthIndex = parent_node_ptr->nodeDepthIndex + 1;
                        parent_node_ptr->Child.push_back(new_node_ptr);
                    } else { // 부모를 못 찾으면 임시 플레이스홀더 부모 생성
                        auto placeholder_parent_ptr = std::make_shared<node::ProcessTreeNode>();
                        placeholder_parent_ptr->AGENT_ID = new_node_ptr->AGENT_ID;
                        placeholder_parent_ptr->session.SessionID = new_node_ptr->session.Parent_SessionID;
                        placeholder_parent_ptr->session.Root_SessionID = new_node_ptr->session.Root_SessionID;
                        placeholder_parent_ptr->shared_tree_timestamp = new_node_ptr->shared_tree_timestamp;
                        placeholder_parent_ptr->nodeDepthIndex = 0;
                        new_node_ptr->nodeDepthIndex = 1;

                        if(new_node_ptr->busy_ref_count)
                            placeholder_parent_ptr->busy_ref_count = new_node_ptr->busy_ref_count;
                        else
                        {
                            placeholder_parent_ptr->busy_ref_count = std::make_shared<std::atomic<unsigned long long>>(0);
                            new_node_ptr->busy_ref_count = placeholder_parent_ptr->busy_ref_count;
                        }
                            

                        if (!new_node_ptr->shared_tree_timestamp) { // 실제 루트가 아직 안 온 경우
                            
                            placeholder_parent_ptr->shared_tree_timestamp = std::make_shared<node::ProcessTreeTimestamp>();
                            unsigned long long now = EDR::Util::timestamp::Get_Real_Timestamp();
                            placeholder_parent_ptr->shared_tree_timestamp->first_seen = now;
                            placeholder_parent_ptr->shared_tree_timestamp->last_seen = now;
                            new_node_ptr->shared_tree_timestamp = placeholder_parent_ptr->shared_tree_timestamp;

                                
                            placeholder_parent_ptr->AssociationRuleCTX = EDRPolicyManager.Get_Cloned_AssociationRuleCTX();
                            if (!new_node_ptr->AssociationRuleCTX) {
                                new_node_ptr->AssociationRuleCTX = placeholder_parent_ptr->AssociationRuleCTX;
                            }
                        } else {
                             placeholder_parent_ptr->shared_tree_timestamp = new_node_ptr->shared_tree_timestamp;
                        }

                        placeholder_parent_ptr->Child.push_back(new_node_ptr);
                        agent_tree.push_back(placeholder_parent_ptr);
                    }
                }

                void _mark_all_nodes_as_terminated(node::ProcessTreeNode& node, node::TerminateReason reason)
                {
                    if (node.is_alive) {
                        node.is_alive = false;
                        node.termination_reason = reason;
                    }
                    for (auto& child : node.Child) {
                        _mark_all_nodes_as_terminated(*child, reason);
                    }
                }

                // Tree가 만들어지고, 비동기적으로 후속작업 진행 함수 ( 1. 인텔리전스 요청 / 2. 룰 매치 )
                void _Async_Tree_Processing(std::shared_ptr<ProcessEvent::Event> eventNode, std::shared_ptr<node::ProcessTreeNode> Node)
                {
                    if (!Node || !eventNode) {
                        std::cerr << "[Async Error] Node or eventNode is null." << std::endl;
                        return;
                    }
                    
                    bool limit_reached;
                    {
                        std::lock_guard<std::mutex> lock(Async_Mutex);
                        limit_reached = (Async_Tree_Processing_asyncs.size() >= MAX_ASYNC_TASKS);
                    }

                    // 한계에 도달했다면 동기적으로 실행
                    if (limit_reached)
                    {
                        _tree_postfix_processing_internal(Node, eventNode);
                        return; // 여기서 함수 종료
                    }
                    else
                    {
                         auto Future = std::async(
                            std::launch::async, [this, eventNode, Node]()
                            {
                                // Async_Tree_Processing_async 비동기 실행
                                _tree_postfix_processing_internal(Node, eventNode);
                            }
                        );


                        {
                            std::lock_guard<std::mutex> lock(Async_Mutex);
                            Async_Tree_Processing_asyncs.emplace_back(
                                std::move( Future ) // 비동기 실행
                            );
                        }
                    }
                    
                }
                void _tree_postfix_processing_internal( std::shared_ptr<EDR::Server::Util::node::ProcessTreeNode> Node, std::shared_ptr<EDR::Server::Util::ProcessEvent::Event> eventNode )
                {
                    /*
                    **********************************************
                        중간 return 은 절대 불가하다. 

                        -> 노드 참조 카운트가 엇갈리면 노드가 종료되지 않아 메모리에 상주하므로 큰일난다. 
                    **********************************************
                    */
                    
                    /*
                        노드 참조 카운트 1 증가
                    */
                    Node->busy_ref_count->fetch_add(1, std::memory_order_seq_cst); // 가시성 보장 ( 값을 읽는 부분에서도 실시간 read로 값 체킹해야하므로 )
                    
                    {
                        try{

                            // 1. 룰 매칭
                            auto Results = Node->AssociationRuleCTX->Match_(eventNode->get_event());
                            Rule_to_Siem(Results);// ToSiem ( Rule )


                            // 2. 인텔리전스 요청 ( 상당히 지연이 크기때문에 맨 나중에 진행. )
                            eventNode->send_to_intelligence();
                            auto intelligence_outputs = eventNode->output_intelligence_result_as_vector();

                            if(!intelligence_outputs.empty())
                            {
                                for(const auto& intelligence : intelligence_outputs)
                                {
                                    std::string Category = intelligence.IntelligenceCategory;
                                    for ( const auto&[Intelligence_Platform, Vectors] : intelligence.intelligence_response.outputs )
                                    {
                                        //std::cout << EDR::Util::Intelligence::QueryEnum_to_String(Intelligence_Platform) << std::endl;
                                        for(const auto& data : Vectors)
                                        {
                                            if( !data.output.empty() )
                                            {
                                                std::string ModuleName = data.ModuleName;
                                                //std::cout << "ModuleName: " << data.ModuleName << std::endl;
                                                std::cout << "JSON: " << data.output[0] << std::endl;

                                                
                                                
                                                for (const auto& JSON : data.output)
                                                    Intelligence_to_Siem(
                                                        fmt::format("ModuleName: {} Content: {}", ModuleName, JSON.dump()),
                                                        Category
                                                    );
                                                
                                            }
                                            

                                        }
                                    }
                                }
                            }

                        }
                        catch ( const std::exception& e )
                        {
                            //std::cerr << "Exception on _Async_Tree_Processing e: " << e.what() << std::endl;
                        }
                        catch ( ... )
                        {
                            //std::cerr << "Exception on _Async_Tree_Processing but IDK" << std::endl;
                        }
                    }

                    Node->busy_ref_count->fetch_sub(1, std::memory_order_seq_cst);
                    
                }

                bool Intelligence_to_Siem( const std::string& detected_intelligence_description, const std::string& category="network"  )
                {
                    SiemClient.Send_Security_Event(
                            "edr",
                            "info", // 인텔리전스는 info로 동일
                            detected_intelligence_description,
                            "",
                            category,
                            "intelligence",
                            EDR::Util::timestamp::Get_Real_Timestamp()
                        );
                    return true;
                }
                bool Rule_to_Siem(const std::vector<Solution::Policy::Resource::Association::RuleMatchedOutput>& Rules)
                {
                    for(auto& rule : Rules)
                    {
                        // 1. 룰 탐지된 경우 무조건 전달
                        SiemClient.Send_Security_Event(
                            "edr",
                            rule.RuleInfo.rule_severity,
                            rule.RuleInfo.rule_description,
                            rule.RuleInfo.false_positive,
                            "behavior",
                            "rule",
                            EDR::Util::timestamp::Get_Real_Timestamp()
                        );

                        // 2. Rule 내, 별도의 Notice등 조치가 있는경우 ( 룰 기반 차단(Response) 가능 )
                        for ( auto& action : rule.actions)
                        {
                            SiemClient.Send_Security_Event(
                                "edr",
                                "info",
                                action.description,
                                "",
                                action.type == Solution::Policy::Resource::Association::Global::ActionType::notice ? "notice" : "response" ,
                                "rule",
                                EDR::Util::timestamp::Get_Real_Timestamp()
                            );

                            // Response
                            if ( action.type == Solution::Policy::Resource::Association::Global::ActionType::block )
                            {
                                // 차단 수행 TCP매니저 인스턴스 상호작용 진행하라.
                            }
                        }
                    }
                }

                //-----------------------------------------

                // 비동기 작업 Async Future 마감 루프 스레드
                void TreeAsyncCleanUpLoopThreat_Function()
                {
                    while (is_TreeManager_Running)
                    {
                        std::lock_guard<std::mutex> lock(Async_Mutex);
                        for (auto it = Async_Tree_Processing_asyncs.begin(); it != Async_Tree_Processing_asyncs.end(); ) {

                            // 블로킹없이 비동기 함수 종료인지 확인포함
                            if (it->valid() && it->wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                                it->get();  // 완료된 작업 회수
                                it = Async_Tree_Processing_asyncs.erase(it); // 벡터에서 제거
                            } else {
                                ++it; // 아직 실행 중이면 다음으로
                            }
                        }
                    }
                }

                // 프로세스 세션 마감 루프 스레드
                void TreeCleanUpLoopThread_Function()
                {
                    while (is_TreeManager_Running)
                    {
                        std::this_thread::sleep_for(std::chrono::seconds(60));
                        if (!is_TreeManager_Running) break;


                        unsigned long long now = EDR::Util::timestamp::Get_Real_Timestamp();
                        
                        std::vector<std::pair<std::string, std::shared_ptr<AgentProcessTree>>> tree_map_snapshot;
                        {
                            std::lock_guard<std::mutex> map_lock(map_mutex);
                            tree_map_snapshot.assign(tree_map.begin(), tree_map.end()); // 복제, 단, 요소/객체는 공유
                        }

                        for (const auto& [agent_id, agent_tree_ptr] : tree_map_snapshot)
                        {
                            std::lock_guard<std::mutex> lock(agent_tree_ptr->mtx);
                            auto& root_nodes = agent_tree_ptr->root_nodes;

                            // 뒤에서부터 순회하며 제거 (erase 안전)
                            for (auto it = root_nodes.rbegin(); it != root_nodes.rend(); ) 
                            {
                                auto& root_node_ptr = *it;
                                bool should_remove = false;

                                //  해당 세션이 busy가 아닌경우에는 종료 처리할 수 없다.
                                std::cout << "root_node_ptr->busy_ref_count->load(std::memory_order_seq_cst): " << root_node_ptr->busy_ref_count->load(std::memory_order_seq_cst) << std::endl; 
                                if ( root_node_ptr->busy_ref_count->load(std::memory_order_seq_cst) != 0 )
                                {
                                    ++it;
                                    continue;
                                }


                                // 조건 1: 루트가 종료되었고 모든 자식도 종료된 경우
                                if (!root_node_ptr->is_alive && root_node_ptr->are_all_children_terminated()) {
                                    should_remove = true;
                                }
                                // 조건 2: 타임아웃
                                else if (root_node_ptr->shared_tree_timestamp && (now - root_node_ptr->shared_tree_timestamp->last_seen > TREE_TIMEOUT_MS)) {
                                    _mark_all_nodes_as_terminated(*root_node_ptr, node::TerminateReason::BY_TIMEOUT);
                                    should_remove = true;
                                }

                                if (should_remove) {
                                    std::cout << "should_remove: True ----> " << std::endl;

                                    // 최상위 노드 필드인 placeholder 값이 (false)인지 확인한다.
                                    // *placehold값이 false인 경우는 정상적으로 해당 세션내 맨 최초의 프로세스 생성(최상위 부모)이벤트를 정상적으로 받았음을 의미.
                                    if(root_node_ptr->is_placeholder == false)
                                    {
                                        // 의도된 정상 로직

                                        json completed_tree;
                                        if (root_node_ptr->to_jsonTree(completed_tree)) {
                                            // 여기까지 True 테스트 됨
                                            CompleteProcessNodeTreeQueue.put(completed_tree);
                                        }
                                    }
                                    // decltype -> 타입 추론
                                    it = decltype(it)(root_nodes.erase(std::next(it).base())); // 해당 부모-자식 세션 완전제거
                                } else {
                                    ++it;
                                }
                            }
                        }
                    }
                }

                void TreeCompletedProcessingThreadRoutine()
                {
                    while (is_TreeManager_Running)
                    {
                        auto CompleteProcessNodeTree = CompleteProcessNodeTreeQueue.get();

                        {
                            /*
                                X 샘플 제작
                            */

                        }
                        
                        
                    }
                    
                }

            }; // class ProcessTreeManager
        }
    }
}

#endif