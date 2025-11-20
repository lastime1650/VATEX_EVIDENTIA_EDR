#ifndef ProcessTree_HPP
#define ProcessTree_HPP

#include "../../../util/util.hpp"
#include "../Solution/_Manager/Manager.hpp" // Solution logics


#include <cmath> // std::log1p 사용을 위해 추가

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
                            exe_size = event["body"]["process"]["exe_size"].get<unsigned long long>();
                            exe_sha256 = event["body"]["process"]["exe_sha256"].get<std::string>();
                            commandline = event["body"]["process"]["commandline"].get<std::string>();

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
                            
                            if( 
                                ( exe_path.find("08a25e1e926752f15b0e2fc79ce07ec41656b6fb55a3da4c0b579a8dc3face0e") != std::string::npos ) ||
                                ( exe_path.find("20c5a2ab17cfa4da1b5238324ce835318943157f35e1edf33ef97eeb9c95a0ad") != std::string::npos ) ||
                                ( exe_path.find("7250ef24caa419dc6aad256cb819fe5523de5e0a7763ca695c15602f01648b8c") != std::string::npos ) ||
                                ( exe_path.find("77c5725ccc9eef27bbc91715a3bd83e21057f429fb16ff45ff2534b8f28a0b6a") != std::string::npos ) 
                            )
                            {
                                std::cout << "[" << exe_path <<  "] 찾음" << std::endl;
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
                    // Root Shared Mutex ( 해당 부모-트리전체에서의 단 하나 mutex)
                    std::shared_ptr<std::mutex> Once_TreeNode_Mutex;

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

                    // --- 누적 스코어링 기반 자동화 차단 스코어 ---
                    std::shared_ptr<std::atomic<unsigned long>> accumulated_risk_score = nullptr;
                    std::shared_ptr<std::atomic<bool>> is_blocked = nullptr; // 차단 신호가 이미 보내졌는가? (기본값 false)

                    // --- 타임스탬프 ---
                    // 이 노드 자체의 이벤트 기반 타임스탬프
                    struct {
                        unsigned long long first_seen = 0;
                        unsigned long long last_seen = 0;
                    } seen_by_event;
                    
                    // 트리 전체의 활동을 추적하기 위해 루트 노드에서 생성되고 공유되는 타임스탬프
                    std::shared_ptr<ProcessTreeTimestamp> shared_tree_timestamp;

                    // --- 분석 및 정책  관련 ---
                    std::shared_ptr<Solution::Policy::Resource::Association::ASSOCIATION_RULE_MANAGER> AssociationRuleCTX = nullptr;

                    std::shared_ptr< 
                        std::map<
                            unsigned long long,                                                                             // 당시 탐지된 실제 이벤트 타임스탬프
                            std::vector<Solution::Policy::Resource::Association::Global::AssociationRuleStruct::Header>     // 탐지된 룰 헤더 정보
                        >
                    > MatchedRules;// 룰 탐지 결과 리스트

                    std::shared_ptr<std::map<
                        std::string,                        // category
                        std::vector< json >             // data
                    >> Intelligences;

                    
                    // --- 헬퍼 함수들 (포인터 기반으로 수정됨) ---

                    // 매칭성공된 룰 기록
                    bool append_matched_rule(const unsigned long long& EventTimestamp, const std::vector<Solution::Policy::Resource::Association::RuleMatchedOutput>& args_matchedRules)
                    {
                        if(args_matchedRules.empty())
                            return false;

                        // key가 "rule"인 룰 전용 event를 생성하고, MatchedRules 필드에 push_back진행
                        (*MatchedRules)[EventTimestamp] = std::vector<Solution::Policy::Resource::Association::Global::AssociationRuleStruct::Header>{};
                        for (auto& rule : args_matchedRules)
                        {
                            
                            (*MatchedRules)[EventTimestamp].push_back( rule.RuleInfo );
                        }

                        return true;
                    }

                    // 인텔리전스 정보 기록
                    bool append_intelligence(const std::string& category, const json& data)
                    {
                        ( (*Intelligences)[category] ).push_back(data);

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

                    unsigned long long get_max_depth() const
                    {
                        unsigned long long max_child_depth = nodeDepthIndex; // 현재 노드 깊이로 초기화

                        for (const auto& child_ptr : Child)
                        {
                            if (child_ptr)
                            {
                                unsigned long long child_depth = child_ptr->get_max_depth();
                                if (child_depth > max_child_depth)
                                    max_child_depth = child_depth;
                            }
                        }

                        return max_child_depth;
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
                        // 전체 정보를 위해서는 "Root 노드에서 실행하라."

                        auto sorted_all_events = get_all_events_sorted_by_time();
                        
                        
                        std::string root_process_sha256 = "";
                        if( session.SessionID == session.Root_SessionID )
                        {
                            try{
                                root_process_sha256 = sorted_all_events[0]["body"]["process"]["exe_sha256"].get<std::string>(); // 보장된 값 (순서정렬된 events 이고, 현재 루트노드이면, [0]인덱스는 무조건 process->create여야만함.)
                            }catch (std::exception& e)
                            {
                                std::cerr << e.what() << std::endl;
                                //throw std::runtime_error(e.what());
                                return false;
                            }
                        }
                        else
                        {
                            // 못찾는 경우,이때는 자신의 SessionID 값이 선정된다 ( 최악 )
                            root_process_sha256 = session.SessionID;
                        }

                        std::cout << "root_process_sha256: " << root_process_sha256 << "root_session: " <<  session.Root_SessionID << std::endl;

                        try {
                            // --- 1. 기본 노드 정보 직렬화 (기존과 동일) ---
                            output = {
                                {"root_process_sha256", root_process_sha256 },
                                {"AGENT_ID", AGENT_ID},
                                {"is_alive", is_alive.load()},
                                {"is_placeholder", is_placeholder.load()},
                                {"nodeDepthIndex", nodeDepthIndex}, // root node에서 하는거면 무조건 0값임
                                {"nodeMaxDepth", get_max_depth()},
                                {"child_count", get_all_child_count()},
                                {"session", {
                                    {"SessionID", session.SessionID},
                                    {"Root_SessionID", session.Root_SessionID},
                                    {"Parent_SessionID", session.Parent_SessionID}
                                }}
                            };
                            // 타임스탬프 정보
                            if (shared_tree_timestamp) {
                                output["timestamp"] = {
                                    {"first_seen", shared_tree_timestamp->first_seen.load()},
                                    {"last_seen", shared_tree_timestamp->last_seen.load()},
                                    {"first_seen_iso8601", EDR::Util::timestamp::To_Nano_Iso8601(shared_tree_timestamp->first_seen.load())},
                                    {"last_seen_iso8601", EDR::Util::timestamp::To_Nano_Iso8601(shared_tree_timestamp->last_seen.load())}
                                };
                            }

                            // --- 2. 'events' 필드 채우기 (수정된 부분) ---
                            output["events"] = sorted_all_events;
                            output["events_count"] = output["events"].size();

                            // --- 3. 'rule' 필드
                            output["rules"] = json::array();
                            for( const auto& [event_timestamp, matched_rules] : *MatchedRules )
                            {
                                for (const auto& matched_rule : matched_rules)
                                {
                                    // 1. MITRE_ATTACK
                                    auto MitreAttack_ARRAY = json::array();
                                    for (const auto mitreattack : matched_rule.mitre_attacks)
                                    {
                                        MitreAttack_ARRAY.push_back(
                                            {
                                                { "tactic_id", mitreattack.tactic_id },
                                                { "technique_id", mitreattack.technique_id },
                                                { "subtechnique_id", mitreattack.subtechnique_id },
                                                { "data_sources", mitreattack.data_sources }
                                            }
                                        );
                                    }
                                    
                                    // 2. PUSH
                                    output["rules"].push_back(
                                        {
                                            {"id", matched_rule.rule_id},
                                            {"name", matched_rule.rule_name},
                                            {"description", matched_rule.rule_description},
                                            {"severity", matched_rule.rule_severity},
                                            {"mitreattacks", MitreAttack_ARRAY},
                                            {"platforms", matched_rule.platforms},
                                            {"operational_usage", matched_rule.operational_usage},
                                            {"false_positive", matched_rule.false_positive},

                                            {"event_timestamp", event_timestamp} // 해당 실제 이벤트
                                            
                                        }
                                    );
                                }
                            }

                            // --- 4. 'intelligence' 필드
                            output["intelligences"] = json::object();
                            for(const auto& [intelligence_category, v] : *Intelligences)
                            {
                                /*
                                    "Category_name": [
                                        {
                                            + "intelligence Infomation" ...
                                            + 'Event_Timestamp'
                                        }
                                    ]
                                */
                                if( !output["intelligences"].contains(intelligence_category) )
                                    output["intelligences"][intelligence_category] = json::array();

                                for (const auto& intelligence_item : v)
                                {
                                    output["intelligences"][intelligence_category].push_back(intelligence_item);
                                }
                                
                            }
                            //std::cout << "intelligences:  " << output["intelligences"].dump() << std::endl;

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
                EDR::Util::File::FileHandler testFileHandle;
                ProcessTreeManager(
                    EDR::Util::ToSiem::SiemClient& SiemClient,
                     Solution::AI::AI_MANAGER& AIManager,
                    Solution::Policy::EDRPolicy& EDRPolicyManager,
                    size_t max_events_per_node = 99999999,
                    size_t max_nodes_per_tree = 1000,
                    size_t MAX_ASYNC_TASKS = 10000,
                    unsigned long long tree_timeout_ms = 300000000 // ?분
                ) : SiemClient(SiemClient),
                    AIManager(AIManager),
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
                            /*
                                ★✪★(◕‿◕) 상속관련 객체 생성 (부모-자식에서 공유하는 객체.)
                            */
                            new_node_ptr->AssociationRuleCTX = EDRPolicyManager.Get_Cloned_AssociationRuleCTX();
                            new_node_ptr->shared_tree_timestamp = std::make_shared<node::ProcessTreeTimestamp>();
                            unsigned long long now = EDR::Util::timestamp::Get_Real_Timestamp();
                            new_node_ptr->shared_tree_timestamp->first_seen.store(now, std::memory_order_seq_cst);
                            new_node_ptr->shared_tree_timestamp->last_seen.store(now, std::memory_order_seq_cst);

                            new_node_ptr->busy_ref_count = std::make_shared<std::atomic<unsigned long long>>(0);
                            new_node_ptr->accumulated_risk_score = std::make_shared<std::atomic<unsigned long>>(0);

                            new_node_ptr->MatchedRules = std::make_shared< std::map< unsigned long long, std::vector<Solution::Policy::Resource::Association::Global::AssociationRuleStruct::Header>> >( );

                            new_node_ptr->Intelligences =  std::make_shared< std::map<std::string,std::vector< json >> >();
                            new_node_ptr->Once_TreeNode_Mutex = std::make_shared<std::mutex>();
                            new_node_ptr->is_blocked = std::make_shared<std::atomic<bool>>(false);

                        } else {
                            if (root_node_ptr) {
                                /*
                                    ★✪★(◕‿◕) 일반적인 상속구간
                                */
                                new_node_ptr->AssociationRuleCTX = root_node_ptr->AssociationRuleCTX;
                                new_node_ptr->shared_tree_timestamp = root_node_ptr->shared_tree_timestamp;
                                new_node_ptr->busy_ref_count = root_node_ptr->busy_ref_count;
                                new_node_ptr->MatchedRules = root_node_ptr->MatchedRules;
                                new_node_ptr->Intelligences = root_node_ptr->Intelligences;
                                new_node_ptr->Once_TreeNode_Mutex = root_node_ptr->Once_TreeNode_Mutex;
                                new_node_ptr->accumulated_risk_score = root_node_ptr->accumulated_risk_score;
                                new_node_ptr->is_blocked = root_node_ptr->is_blocked;
                            }
                        }

                        if (new_node_ptr->shared_tree_timestamp) {
                            new_node_ptr->shared_tree_timestamp->last_seen.store(EDR::Util::timestamp::Get_Real_Timestamp(), std::memory_order_seq_cst);
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
                        if( node_for_async->session.Root_SessionID == "bc8771751e7dc43a8f7a02e91932c462cc13d47172d32208e27097c4ed162d5a" )
                        {
                            std::string X = eventNode->get_event().dump() + ",\n";
                            testFileHandle.writeToFile("./test.json", std::vector<uint8_t>(X.begin(), X.end()), true);
                        }
                    }
                    // --- 시나리오 2: 노드가 이미 존재함 ---
                    else
                    {
                        if (!target_node_ptr->is_alive) { // 이미 종료된 노드에는 이벤트 추가 안 함
                            return false;
                        }

                        // 노드 당 최대 수용가능한 이벤트 개수 설정 (events limit)
                        if (target_node_ptr->events.size() >= MAX_EVENTS_PER_NODE) {
                            target_node_ptr->is_alive = false;
                            target_node_ptr->termination_reason = node::TerminateReason::BY_MAX_EVENTS_LIMIT;
                            return false; // 새 이벤트 추가 거부
                        }

                        target_node_ptr->events.push_back(eventNode);
                        target_node_ptr->seen_by_event.last_seen = std::max(target_node_ptr->seen_by_event.last_seen, eventNode->timestamp);
                        
                        if (target_node_ptr->shared_tree_timestamp) {
                            target_node_ptr->shared_tree_timestamp->last_seen.store(EDR::Util::timestamp::Get_Real_Timestamp(), std::memory_order_seq_cst);
                        }

                        if (target_node_ptr->is_placeholder && dynamic_cast<ProcessEvent::ProcessCreateEvent*>(eventNode.get())) {
                            target_node_ptr->is_placeholder = false;
                            std::rotate(target_node_ptr->events.rbegin(), target_node_ptr->events.rbegin() + 1, target_node_ptr->events.rend());
                        }

                        if (dynamic_cast<ProcessEvent::ProcessTerminateEvent*>(eventNode.get())) {
                            //target_node_ptr->is_alive = false;
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
                Solution::AI::AI_MANAGER& AIManager;
                Solution::Policy::EDRPolicy& EDRPolicyManager;
                const size_t MAX_EVENTS_PER_NODE;
                const size_t MAX_NODES_PER_TREE;
                const size_t MAX_ASYNC_TASKS;
                const unsigned long long TREE_TIMEOUT_MS;

                using TreeMap = std::map<std::string, std::shared_ptr<AgentProcessTree>>;
                TreeMap tree_map;
                std::mutex map_mutex; // TreeMap 자체를 보호하기 위한 뮤텍스

                // Queue
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
                        /*
                            ★✪★(◕‿◕) 상속구간
                        */
                        new_node_ptr->AssociationRuleCTX = parent_node_ptr->AssociationRuleCTX;
                        new_node_ptr->shared_tree_timestamp = parent_node_ptr->shared_tree_timestamp;
                        new_node_ptr->busy_ref_count = parent_node_ptr->busy_ref_count;
                        new_node_ptr->MatchedRules = parent_node_ptr->MatchedRules;
                        new_node_ptr->Intelligences = parent_node_ptr->Intelligences;
                        new_node_ptr->Once_TreeNode_Mutex = parent_node_ptr->Once_TreeNode_Mutex;
                        new_node_ptr->accumulated_risk_score = parent_node_ptr->accumulated_risk_score;
                        new_node_ptr->is_blocked = parent_node_ptr->is_blocked;

                        new_node_ptr->nodeDepthIndex = parent_node_ptr->nodeDepthIndex + 1;
                        parent_node_ptr->Child.push_back(new_node_ptr);
                    } else { // 직계부모를 못 찾으면 임시 플레이스홀더 부모 생성
                        /*
                            ★✪★(◕‿◕) 생성 + 상속구간
                        */
                        auto placeholder_parent_ptr = std::make_shared<node::ProcessTreeNode>();
                        placeholder_parent_ptr->AGENT_ID = new_node_ptr->AGENT_ID;
                        placeholder_parent_ptr->session.SessionID = new_node_ptr->session.Parent_SessionID;
                        placeholder_parent_ptr->session.Root_SessionID = new_node_ptr->session.Root_SessionID;
                        placeholder_parent_ptr->shared_tree_timestamp = new_node_ptr->shared_tree_timestamp;
                        placeholder_parent_ptr->nodeDepthIndex = 0;
                        new_node_ptr->nodeDepthIndex = 1;

                        // [수정 시작] 모든 공유 포인터를 명시적으로 생성하고 상속
                        auto new_busy_ref = std::make_shared<std::atomic<unsigned long long>>(0);
                        placeholder_parent_ptr->busy_ref_count = new_busy_ref;
                        new_node_ptr->busy_ref_count = new_busy_ref; // 자식도 동일한 포인터 공유

                        auto new_rules_vec = std::make_shared< std::map<unsigned long long, std::vector<Solution::Policy::Resource::Association::Global::AssociationRuleStruct::Header>> > ();
                        placeholder_parent_ptr->MatchedRules = new_rules_vec;

                        if(new_node_ptr->session.Root_SessionID == "bc8771751e7dc43a8f7a02e91932c462cc13d47172d32208e27097c4ed162d5a")
                            std::cout << "new_node_ptr->MatchedRules: " << new_node_ptr->MatchedRules << " new_rules_vec: " << new_rules_vec << std::endl;
                        new_node_ptr->MatchedRules = new_rules_vec;

                        
                        auto new_accumulated_risk_score = std::make_shared<std::atomic<unsigned long>>(0);
                        placeholder_parent_ptr->accumulated_risk_score = new_accumulated_risk_score;
                        new_node_ptr->accumulated_risk_score = new_accumulated_risk_score; // 자식도 동일한 포인터 공유

                        auto new_is_blocked = std::make_shared<std::atomic<bool>>(false);
                        placeholder_parent_ptr->is_blocked = new_is_blocked;
                        new_node_ptr->is_blocked = new_is_blocked; // 자식도 동일한 포인터 공유

                        auto new_mutex = std::make_shared<std::mutex>();
                        placeholder_parent_ptr->Once_TreeNode_Mutex = new_mutex;
                        new_node_ptr->Once_TreeNode_Mutex = new_mutex;

                        auto new_intel_map = std::make_shared<std::map<std::string, std::vector<json>>>();
                        placeholder_parent_ptr->Intelligences = new_intel_map;
                        new_node_ptr->Intelligences = new_intel_map;

                        auto new_rule_ctx = EDRPolicyManager.Get_Cloned_AssociationRuleCTX();
                        placeholder_parent_ptr->AssociationRuleCTX = new_rule_ctx;
                        new_node_ptr->AssociationRuleCTX = new_rule_ctx;
                            

                        if (!new_node_ptr->shared_tree_timestamp) { // 실제 루트가 아직 안 온 경우
                            
                            placeholder_parent_ptr->shared_tree_timestamp = std::make_shared<node::ProcessTreeTimestamp>();
                            unsigned long long now = EDR::Util::timestamp::Get_Real_Timestamp();
                            placeholder_parent_ptr->shared_tree_timestamp->first_seen = now;
                            placeholder_parent_ptr->shared_tree_timestamp->last_seen = now;
                            new_node_ptr->shared_tree_timestamp = placeholder_parent_ptr->shared_tree_timestamp;

                                
                            //placeholder_parent_ptr->AssociationRuleCTX = EDRPolicyManager.Get_Cloned_AssociationRuleCTX();
                           // if (!new_node_ptr->AssociationRuleCTX) {
                            //    new_node_ptr->AssociationRuleCTX = placeholder_parent_ptr->AssociationRuleCTX;
                            //}
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

                // Tree가 만들어지고, 비동기적으로 후속작업 진행 함수 (  인텔리전스 요청 , 룰 매치 )
                void _Async_Tree_Processing(std::shared_ptr<ProcessEvent::Event> eventNode, std::shared_ptr<node::ProcessTreeNode> Node)
                {
                    /*
                        1차 검증된
                    */

                    //_tree_postfix_processing_internal(Node, eventNode);

                     
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

                            auto EventLogJson = eventNode->get_event();

                             // EDR에서 탐지된 (1)MITRE_ATTACK연동 행위 탐지 결과, (2) 인텔리전스 서버 결과 포함
                            EventLogJson["threat"]["rules"] = json::array();
                            EventLogJson["threat"]["intelligences"] = json::array();

                            {
                                
                                std::vector<Solution::Policy::Resource::Association::RuleMatchedOutput> Results{};
                                // 1. 룰 및 일관성처리 (이 메서드내 높은 우선순위)
                                try
                                {
                                    std::lock_guard<std::mutex> lock2(*Node->Once_TreeNode_Mutex);
                                    
                                    // 1. 룰 매칭
                                    Results = Node->AssociationRuleCTX->Match_(eventNode->get_event());
                                }
                                catch(const std::exception& e)
                                {
                                    std::cerr << "_tree_postfix_processing_internal -> ERROR: " << e.what() << '\n';
                                }

                                // 룰 매칭 성공 post작업 ( 파싱 )
                                if(!Results.empty())
                                {
                                    // Append Raw-Edr Event Log
                                    for (const auto& detected_rule : Results)
                                    {
                                        auto matched_rule = detected_rule.RuleInfo;

                                        // Severity to score + Risk_Scoring
                                        /*
                                            "INFO" => 0,
                                            "LOW" => 10,
                                            "MEDIUM" => 30,
                                            "HIGH" => 70,
                                            "CRITICAL" => 100
                                        */
                                        unsigned int score = 0;
                                        if( matched_rule.rule_severity == "low" )
                                            score = 10;
                                        else if( matched_rule.rule_severity == "medium" )
                                            score = 30;
                                        else if( matched_rule.rule_severity == "high" )
                                            score = 70;
                                        else if( matched_rule.rule_severity == "critical" )
                                            score = 100;

                                        int previous_risk_score = Node->accumulated_risk_score->fetch_add(score, std::memory_order_seq_cst);
                                        if( !Node->is_blocked->load(std::memory_order_seq_cst) && ( previous_risk_score + score ) )
                                        {
                                            /*
                                                차단 진행
                                            */
                                           Scoring_Block_to_Siem(Node->session.Root_SessionID); // 차단 신호 전달

                                           // Security-Threat로 차단 신호 전송
                                           Node->is_blocked->store(true, std::memory_order_seq_cst);
                                        }
                                        
                                        
                                       

                                        // 1. MITRE_ATTACK
                                        auto MitreAttack_ARRAY = json::array();
                                        for (const auto mitreattack : matched_rule.mitre_attacks)
                                        {
                                            MitreAttack_ARRAY.push_back(
                                                {
                                                    { "tactic_id", mitreattack.tactic_id },
                                                    { "technique_id", mitreattack.technique_id },
                                                    { "subtechnique_id", mitreattack.subtechnique_id },
                                                    { "data_sources", mitreattack.data_sources }
                                                }
                                            );

                                            EventLogJson["threat"]["rules"].push_back(
                                                {
                                                    {"id", matched_rule.rule_id},
                                                    {"name", matched_rule.rule_name},
                                                    {"description", matched_rule.rule_description},
                                                    {"severity", matched_rule.rule_severity},
                                                    {"mitreattacks", MitreAttack_ARRAY},
                                                    {"platforms", matched_rule.platforms},
                                                    {"operational_usage", matched_rule.operational_usage},
                                                    {"false_positive", matched_rule.false_positive}
                                                }
                                            );
                                        }


                                    }
                                    
                                    Rule_to_Siem(Node->session.Root_SessionID, Results);// ToSiem ( Rule ) <Security-Threat Index>
                                    //Node->append_matched_rule(eventNode->timestamp, Results); //Node에 기록
                                }
                                
                                
                            }

                            // 3. 인텔리전스 요청 ( 상당히 지연이 크기때문에 맨 나중에 진행. )
                            /*eventNode->send_to_intelligence();
                            auto intelligence_outputs = eventNode->output_intelligence_result_as_vector();

                            if(!intelligence_outputs.empty())
                            {
                                for(const auto& intelligence : intelligence_outputs)
                                {
                                    std::string Category = intelligence.IntelligenceCategory;
                                    for ( const auto&[Intelligence_Platform, Vectors] : intelligence.intelligence_response.outputs )
                                    {
                                        for(const auto& data : Vectors)
                                        {
                                            if( !data.output.empty() )
                                            {
                                                std::string ModuleName = data.ModuleName;

                                                
                                                
                                                for (const auto& JSON : data.output)
                                                {
                                                    Intelligence_to_Siem(
                                                        fmt::format("ModuleName: {} Content: {}", ModuleName, JSON.dump()),
                                                        Category
                                                    );

                                                    Node->append_intelligence(
                                                        Category,
                                                        JSON
                                                    );
                                                }
                                                    
                                                
                                            }
                                            

                                        }
                                    }
                                }
                            }*/


                            // (Finish) 해당 로그를 SIEM->RAW에 전달
                            /*
                                여러 Document로 이벤트 전달하는 형식으로 변경됨
                            */
                            SiemClient.Send_RAW_EDR_INDEX_Event(
                                EventLogJson
                            );

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

                bool Intelligence_to_Siem( const std::string& Root_Process_Id, const std::string& detected_intelligence_description, const std::string& category="network"  )
                {
                    SiemClient.Send_Security_Event(
                            "edr",
                            "info", // 인텔리전스는 info로 동일
                            detected_intelligence_description,
                            "",
                            category,
                            "intelligence",
                            Root_Process_Id,
                            EDR::Util::timestamp::Get_Real_Timestamp()
                        );
                    return true;
                }

                void Scoring_Block_to_Siem(const std::string& Root_Process_Id)
                {
                    SiemClient.Send_Security_Event(
                        "edr",
                        "",
                        "",
                        "",
                        "block",
                        "scoring",
                        Root_Process_Id,
                        EDR::Util::timestamp::Get_Real_Timestamp()
                    );
                }

                bool Rule_to_Siem(const std::string& Root_Process_Id, const std::vector<Solution::Policy::Resource::Association::RuleMatchedOutput>& Rules)
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
                            Root_Process_Id,
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
                                action.type == Solution::Policy::Resource::Association::Global::ActionType::notice ? "notice" : "block" ,
                                "rule",
                                Root_Process_Id,
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
                                else if (root_node_ptr->shared_tree_timestamp && (now - root_node_ptr->shared_tree_timestamp->last_seen.load(std::memory_order_seq_cst) > TREE_TIMEOUT_MS)) {
                                    _mark_all_nodes_as_terminated(*root_node_ptr, node::TerminateReason::BY_TIMEOUT);
                                    should_remove = true;
                                }

                                if (should_remove) {

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
                        if (CompleteProcessNodeTree.is_null()) continue;

                        auto CompleteProcessNodeTree_Unique = std::make_unique<json>(CompleteProcessNodeTree);


                        bool limit_reached;
                        {
                            std::lock_guard<std::mutex> lock(Async_Mutex);
                            limit_reached = (Async_Tree_Processing_asyncs.size() >= MAX_ASYNC_TASKS);
                        }

                        // 한계에 도달했다면 동기적으로 실행
                        if (limit_reached)
                        {
                            __TreeCompletedProcessingThreadRoutine(std::move(CompleteProcessNodeTree_Unique));
                            return; // 여기서 함수 종료
                        }

                        auto Future = std::async(
                            std::launch::async, [this, Postfix_CompleteProcessNodeTree = std::move( CompleteProcessNodeTree_Unique )]() mutable
                            {
                                // 비동기 프로세스 세션 전체 POST 처리 ( SIEM , AI etc .. ) < "프로세스 트리 인스턴스" 완전 최종 단계 >
                                __TreeCompletedProcessingThreadRoutine(std::move(Postfix_CompleteProcessNodeTree));
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

                void __TreeCompletedProcessingThreadRoutine(std::unique_ptr<json> Postfix_CompleteProcessNodeTree ) // Unique Owner is move here ! 
                {
                    {
                        //======================================================================
                        //  RAW-EDR ---- SIEM 전송
                        //======================================================================
                        /*try
                        {
                            // To Siem < Send_RAW_EDR_INDEX_Event >
                            SiemClient.Send_RAW_EDR_INDEX_Event(*Postfix_CompleteProcessNodeTree); // To Siem
                        }catch (std::exception& e)
                        {
                            std::cerr << e.what() << std::endl;
                        }*/

                        //======================================================================
                        //  AGGREGATION-EDR ---- SIEM 전송
                        //
                        //======================================================================
                        
                    }

                    try
                    {
                        std::vector<double> feature_vector;

                        
                        //======================================================================
                        // [1/3] 세션 정보 ---- 샘플 구하기
                        //======================================================================
                        __get_sample_SessionInfo(feature_vector, *Postfix_CompleteProcessNodeTree);


                        


                        //======================================================================
                        // [2/3] 탐지된 룰 정보 ---- 샘플 구하기
                        //===================================================================Postfix_CompleteProcessNodeTree===
                        __get_sample_RuleInfo(feature_vector, *Postfix_CompleteProcessNodeTree);




                        //======================================================================
                        // [3/3] 탐지된 인텔리전스 ---- 정보 샘플 구하기
                        //======================================================================
                        __get_sample_IntelligenceInfo(feature_vector, *Postfix_CompleteProcessNodeTree);
                        


                        
                        
                        //======================================================================
                        // 최종 피처 벡터 처리
                        //======================================================================
                        
                        std::cout << "Generated Feature Vector for Session " << (*Postfix_CompleteProcessNodeTree).value("root_process_sha256", "???????") 
                                << " (size: " << feature_vector.size() << "): ";

                        for(size_t i = 0; i < feature_vector.size(); ++i) {
                            std::cout << feature_vector[i] << (i == feature_vector.size() - 1 ? "" : ", ");
                        }
                        std::cout << std::endl;

                        
                        // Finish 
                        //======================================================================
                        // Send to AIManager Instance
                        //======================================================================


                        // 1. MachineLearning 
                        unsigned long long x_sample_count = 0;
                        std::cout << "AiManager.is_Possible_Train(): " << AIManager.is_Possible_Train(&x_sample_count) << " x_sample_cout: " << x_sample_count << std::endl;

                        // Sample X+y Send to NOVA_AI
                        
                        // Classification - A
                        std::cout << "WithId_Sample_Push_Path_Classification Calling() " << std::endl;
                        AIManager.PushData(
                            (*Postfix_CompleteProcessNodeTree)["root_process_sha256"].get<std::string>(),
                            feature_vector,
                            "normal"
                        );
                        std::cout << "WithId_Sample_Push_Path_Classification Completed " << std::endl;



                    }
                    catch (const std::exception& e)
                    {
                        std::cerr << "Error processing completed tree: " << e.what() << std::endl;
                        if ((*Postfix_CompleteProcessNodeTree).is_object()) {
                            //std::cerr << "Problematic JSON: " << CompleteProcessNodeTree.dump(2) << std::endl;
                        }
                    }

                }
                
                // [1/3] 이벤트 세션 정보 - 샘플 섹션
                void __get_sample_SessionInfo(std::vector<double>& feature_vector, json& CompleteProcessNodeTree)
                {
                    //======================================================================
                    // [A] --- 세션/트리 전체 정보 (Global Features) ---
                    //======================================================================
                    const unsigned long long total_event_count = CompleteProcessNodeTree.value("events_count", 0ULL);
                    feature_vector.push_back(static_cast<double>(total_event_count));

                    const unsigned long long child_node_count = CompleteProcessNodeTree.value("child_count", 0ULL);
                    feature_vector.push_back(static_cast<double>(child_node_count));
                    
                    unsigned long long first_seen_ts = 0, last_seen_ts = 0;
                    if (CompleteProcessNodeTree.contains("shared_tree_timestamp") && CompleteProcessNodeTree["shared_tree_timestamp"].is_object()) {
                        first_seen_ts = CompleteProcessNodeTree["shared_tree_timestamp"].value("first_seen", 0ULL);
                        last_seen_ts = CompleteProcessNodeTree["shared_tree_timestamp"].value("last_seen", 0ULL);
                    }
                    const unsigned long long session_duration_ms = (last_seen_ts > first_seen_ts) ? (last_seen_ts - first_seen_ts) : 1;
                    //feature_vector.push_back(static_cast<double>(session_duration_ms)); 값이 너무 크다
                    feature_vector.push_back(std::log1p(static_cast<double>(session_duration_ms)));
                    
                    //const double events_per_second = static_cast<double>(total_event_count) / (static_cast<double>(session_duration_ms) / 1000.0);
                    //feature_vector.push_back(events_per_second); // 너무 0으로 작아지는 것을 방지
                    const double session_duration_sec = static_cast<double>(session_duration_ms) / 1000.0;
                    const double epsilon = 1e-6; // 0으로 나누는 것을 방지하기 위한 작은 값
                    const double events_per_second = static_cast<double>(total_event_count) / (session_duration_sec + epsilon);
                    feature_vector.push_back(events_per_second);

                    //======================================================================
                    // [B] --- 이벤트 기반 통계 (Event-based Statistics) ---
                    //======================================================================
                    
                    // 이벤트 유형별 카운트를 저장할 맵
                    std::map<std::string, unsigned long long> event_type_counts;
                    
                    // 더 세분화된 행위 카운트
                    std::map<std::string, unsigned long long> fs_action_counts;
                    std::map<std::string, unsigned long long> reg_action_counts;
                    
                    
                    unsigned long long outbound_connection_count = 0;
                    std::set<std::string> loaded_dlls;

                    const auto& events = CompleteProcessNodeTree.value("events", json::array());
                    for (const auto& event_json : events)
                    {
                        const auto& header = event_json.value("header", json::object());
                        const auto& body = event_json.value("body", json::object());
                        if (body.empty()) continue;

                        // --- 이벤트 유형 식별 (body의 첫 번째 키 사용) ---
                        const auto& [event_type, event_data] = *body.items().begin();
                        
                        // --- 이벤트 유형별 카운팅 및 세부 분석 ---
                        event_type_counts[event_type]++;

                        if (event_type == "process") {
                            std::string action = event_data.value("action", "");
                            if (action == "create") event_type_counts["process_create"]++;
                            else if (action == "remove") event_type_counts["process_terminate"]++;
                        }
                        else if (event_type == "network") {
                            if (event_data.value("direction", "") == "out") outbound_connection_count++;
                        }
                        else if (event_type == "filesystem") {
                            fs_action_counts[event_data.value("action", "")]++;
                        }
                        else if (event_type == "imageload") {
                            loaded_dlls.insert(event_data.value("filepath", ""));
                        }
                        else if (event_type == "registry") {
                            reg_action_counts[event_data.value("keyclass", "")]++;
                        }
                        
                        
                    }

                    // 최대 트리 깊이
                    unsigned long long max_depth = CompleteProcessNodeTree.value("nodeMaxDepth", 0ULL);;
                    feature_vector.push_back(static_cast<double>(max_depth));

                    // B-1. 주요 이벤트 유형별 총 개수
                    feature_vector.push_back(static_cast<double>(event_type_counts["process_create"]));
                    feature_vector.push_back(static_cast<double>(event_type_counts["process_terminate"]));
                    feature_vector.push_back(static_cast<double>(event_type_counts["network"]));
                    feature_vector.push_back(static_cast<double>(event_type_counts["filesystem"]));
                    feature_vector.push_back(static_cast<double>(event_type_counts["imageload"]));
                    feature_vector.push_back(static_cast<double>(event_type_counts["registry"]));
                    feature_vector.push_back(static_cast<double>(event_type_counts["processaccess"]));
                    feature_vector.push_back(static_cast<double>(event_type_counts["apicall"]));
                    feature_vector.push_back(static_cast<double>(event_type_counts["etw"]));

                    // B-2. 파일시스템 세부 행위 카운트
                    feature_vector.push_back(static_cast<double>(fs_action_counts["create"]));
                    feature_vector.push_back(static_cast<double>(fs_action_counts["write"]));
                    feature_vector.push_back(static_cast<double>(fs_action_counts["delete"]));
                    feature_vector.push_back(static_cast<double>(fs_action_counts["rename"]));
                    feature_vector.push_back(static_cast<double>(fs_action_counts["open"]));
                    feature_vector.push_back(static_cast<double>(fs_action_counts["overwritten"]));
                    feature_vector.push_back(static_cast<double>(fs_action_counts["superseded"]));
                    feature_vector.push_back(static_cast<double>(fs_action_counts["exists"]));
                    feature_vector.push_back(static_cast<double>(fs_action_counts["create_directory"]));
                    feature_vector.push_back(static_cast<double>(fs_action_counts["remove_directory"]));
                    feature_vector.push_back(static_cast<double>(fs_action_counts["rename_directory"]));


                    // B-3. 레지스트리 세부 행위 카운트
                    feature_vector.push_back(static_cast<double>(reg_action_counts["PreCreateKeyEx"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["PreQueryKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["PreQueryValueKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["PreQueryMultipleValueKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["PreKeyHandleClose"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreFlushKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreLoadKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreUnLoadKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreQueryKeySecurity"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreSetKeySecurity"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreRestoreKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreSaveKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["PreReplaceKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["PreQueryKeyName"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["PreSaveMergedKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreSetValueKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreDeleteValueKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreSetInformationKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreEnumerateKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreEnumerateValueKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreCreateKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreOpenKey"]));
                    feature_vector.push_back(static_cast<double>(reg_action_counts["RegNtPreOpenKeyEx"]));

                    // B-4 "비율" - 전체비중들
                    unsigned long long total_events = 0;
                    for(const auto& [action, count] : event_type_counts) { // 파일 시스템 이벤트의 총합 계산
                        total_events += count;
                    }
                    feature_vector.push_back(static_cast<double>(  (total_events > 0) ? static_cast<double>(event_type_counts["process_create"]) / total_events : 0.0 )); // 전체 행위 중의 "process_create" 비율
                    feature_vector.push_back(static_cast<double>(  (total_events > 0) ? static_cast<double>(event_type_counts["process_terminate"]) / total_events : 0.0 )); // 전체 행위 중의 "process_terminate" 비율
                    feature_vector.push_back(static_cast<double>(  (total_events > 0) ? static_cast<double>(event_type_counts["network"]) / total_events : 0.0 )); // 전체 행위 중의 "network" 비율
                    feature_vector.push_back(static_cast<double>(  (total_events > 0) ? static_cast<double>(event_type_counts["filesystem"]) / total_events : 0.0 )); // 전체 행위 중의 "filesystem" 비율
                    feature_vector.push_back(static_cast<double>(  (total_events > 0) ? static_cast<double>(event_type_counts["imageload"]) / total_events : 0.0 )); // 전체 행위 중의 "imageload" 비율
                    feature_vector.push_back(static_cast<double>(  (total_events > 0) ? static_cast<double>(event_type_counts["registry"]) / total_events : 0.0 )); // 전체 행위 중의 "registry" 비율
                    feature_vector.push_back(static_cast<double>(  (total_events > 0) ? static_cast<double>(event_type_counts["processaccess"]) / total_events : 0.0 )); // 전체 행위 중의 "processaccess" 비율
                    feature_vector.push_back(static_cast<double>(  (total_events > 0) ? static_cast<double>(event_type_counts["apicall"]) / total_events : 0.0 )); // 전체 행위 중의 "apicall" 비율
                    feature_vector.push_back(static_cast<double>(  (total_events > 0) ? static_cast<double>(event_type_counts["etw"]) / total_events : 0.0 )); // 전체 행위 중의 "etw" 비율
                    

                    // B-5 "비율" - 파일시스템
                    unsigned long long total_fs_events = 0;
                    for(const auto& [action, count] : fs_action_counts) { // 파일 시스템 이벤트의 총합 계산
                        total_fs_events += count;
                    }
                    feature_vector.push_back(static_cast<double>(  (total_fs_events > 0) ? static_cast<double>(fs_action_counts["create"]) / total_fs_events : 0.0 )); // 전체 파일시스템 행위 중의 "create" 비율
                    feature_vector.push_back(static_cast<double>(  (total_fs_events > 0) ? static_cast<double>(fs_action_counts["write"]) / total_fs_events : 0.0 )); // 전체 파일시스템 행위 중의 "write" 비율
                    feature_vector.push_back(static_cast<double>(  (total_fs_events > 0) ? static_cast<double>(fs_action_counts["delete"]) / total_fs_events : 0.0 )); // 전체 파일시스템 행위 중의 "delete" 비율
                    feature_vector.push_back(static_cast<double>(  (total_fs_events > 0) ? static_cast<double>(fs_action_counts["rename"]) / total_fs_events : 0.0 )); // 전체 파일시스템 행위 중의 "rename" 비율
                    feature_vector.push_back(static_cast<double>(  (total_fs_events > 0) ? static_cast<double>(fs_action_counts["open"]) / total_fs_events : 0.0 )); // 전체 파일시스템 행위 중의 "open" 비율
                    feature_vector.push_back(static_cast<double>(  (total_fs_events > 0) ? static_cast<double>(fs_action_counts["overwritten"]) / total_fs_events : 0.0 )); // 전체 파일시스템 행위 중의 "overwritten" 비율
                    feature_vector.push_back(static_cast<double>(  (total_fs_events > 0) ? static_cast<double>(fs_action_counts["superseded"]) / total_fs_events : 0.0 )); // 전체 파일시스템 행위 중의 "superseded" 비율
                    feature_vector.push_back(static_cast<double>(  (total_fs_events > 0) ? static_cast<double>(fs_action_counts["exists"]) / total_fs_events : 0.0 )); // 전체 파일시스템 행위 중의 "exists" 비율
                    feature_vector.push_back(static_cast<double>(  (total_fs_events > 0) ? static_cast<double>(fs_action_counts["create_directory"]) / total_fs_events : 0.0 )); // 전체 파일시스템 행위 중의 "create_directory" 비율
                    feature_vector.push_back(static_cast<double>(  (total_fs_events > 0) ? static_cast<double>(fs_action_counts["remove_directory"]) / total_fs_events : 0.0 )); // 전체 파일시스템 행위 중의 "remove_directory" 비율
                    feature_vector.push_back(static_cast<double>(  (total_fs_events > 0) ? static_cast<double>(fs_action_counts["rename_directory"]) / total_fs_events : 0.0 )); // 전체 파일시스템 행위 중의 "rename_directory" 비율

                    // B-6 "비율" - 레지스트리
                    unsigned long long total_reg_events = 0;
                    for(const auto& [action, count] : reg_action_counts) { // 파일 시스템 이벤트의 총합 계산
                        total_reg_events += count;
                    }
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["PreCreateKeyEx"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["PreQueryKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["PreQueryValueKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["PreQueryMultipleValueKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["PreKeyHandleClose"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreFlushKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreLoadKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreUnLoadKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreQueryKeySecurity"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreSetKeySecurity"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreRestoreKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreSaveKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["PreReplaceKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["PreQueryKeyName"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["PreSaveMergedKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreSetValueKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreDeleteValueKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreSetInformationKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreEnumerateKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreEnumerateValueKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreCreateKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreOpenKey"]) / total_reg_events : 0.0 );
                    feature_vector.push_back( (total_reg_events > 0) ? static_cast<double>(reg_action_counts["RegNtPreOpenKeyEx"]) / total_reg_events : 0.0 );

                    //======================================================================
                    // [C] --- 콘텐츠 기반 통계 피처 벡터에 추가 ---
                    //======================================================================
                    feature_vector.push_back(static_cast<double>(outbound_connection_count));
                    feature_vector.push_back(static_cast<double>(loaded_dlls.size())); // 고유 DLL 로드 수

                    // 새로 추가: 프로세스 생성 대비 DLL 로드 비율 (프로세스 인젝션 의심)
                    double dll_per_proc_ratio = 0.0;
                    if (event_type_counts["process_create"] > 0) {
                        dll_per_proc_ratio = static_cast<double>(loaded_dlls.size()) / event_type_counts["process_create"];
                    }
                    feature_vector.push_back(dll_per_proc_ratio);

                    // 새로 추가: 네트워크 이벤트 대비 아웃바운드 비율
                    double outbound_ratio = 0.0;
                    if (event_type_counts["network"] > 0) {
                        outbound_ratio = static_cast<double>(outbound_connection_count) / event_type_counts["network"];
                    }
                    feature_vector.push_back(outbound_ratio);
                }
                // [2/3] 이벤트 룰 정보<Mitreattack등> - 샘플 섹션
                void __get_sample_RuleInfo(std::vector<double>& feature_vector, json& CompleteProcessNodeTree)
                {
                    //======================================================================
                            // [D] --- 룰 정보 ---
                            //======================================================================

                            std::map<std::string, unsigned long long> event_type_counts;

                            // D-1. 탐지된 룰 개수 전체
                            const unsigned long long matched_rule_count = CompleteProcessNodeTree.value("rules", json::array()).size();
                            // D-2. 탐지된 info 심각도 룰 개수
                            unsigned long long matched_rule_severity_info_count = 0;
                            // D-3. 탐지된 low 심각도 룰 개수
                            unsigned long long matched_rule_severity_low_count = 0;
                            // D-4. 탐지된 medium 심각도 룰 개수
                            unsigned long long matched_rule_severity_medium_count = 0;
                            // D-5. 탐지된 high 심각도 룰 개수
                            unsigned long long matched_rule_severity_high_count = 0;
                            // D-6. 탐지된 critical 심각도 룰 개수
                            unsigned long long matched_rule_severity_critical_count = 0;

                            // D-7. MitreAttack 
                            for(const auto& data : CompleteProcessNodeTree["rules"])
                            {
                                /*
                                    // 1. MITRE_ATTACK
                                    auto MitreAttack_ARRAY = json::array();
                                    for (const auto mitreattack : matched_rule.mitre_attacks)
                                    {
                                        MitreAttack_ARRAY.push_back(
                                            {
                                                { "tactic_id", mitreattack.tactic_id },
                                                { "technique_id", mitreattack.technique_id },
                                                { "subtechnique_id", mitreattack.subtechnique_id },
                                                { "data_sources", mitreattack.data_sources }
                                            }
                                        );
                                    }
                                    
                                    // 2. PUSH
                                    output["rules"].push_back(
                                        {
                                            {"id", matched_rule.rule_id},
                                            {"name", matched_rule.rule_name},
                                            {"description", matched_rule.rule_description},
                                            {"severity", matched_rule.rule_severity},
                                            {"mitreattacks", MitreAttack_ARRAY},
                                            {"platforms", matched_rule.platforms},
                                            {"operational_usage", matched_rule.operational_usage},
                                            {"false_positive", matched_rule.false_positive},
                                            
                                        }
                                    );
                                */

                                for(const auto& [k,v] : data.items())
                                {
                                    //std::cout << "data_k: " << k << std::endl;
                                    // A. 심각도
                                    if(k == "severity")
                                    {
                                        if(v.get<std::string>() == "info")
                                            matched_rule_severity_info_count++;
                                        else if (v.get<std::string>() == "low")
                                            matched_rule_severity_low_count++;
                                        else if (v.get<std::string>() == "medium")
                                            matched_rule_severity_medium_count++;
                                        else if (v.get<std::string>() == "high")
                                            matched_rule_severity_high_count++;
                                        else if (v.get<std::string>() == "critical")
                                            matched_rule_severity_critical_count++;
                                        else
                                            continue;
                                    }
                                    else if ( k == "mitreattacks" )
                                    {
                                        //std::cout << "[mitreattacks] v.size: " << v.size() << std::endl;
                                        for(const auto& MitreAttackData : v.get<std::vector<json>>())
                                        {
                                            //std::cout << "MitreAttackData-DUMP: " << MitreAttackData.dump() << std::endl;
                                            for(const auto& [mitreattack_k,mitreattack_v] : MitreAttackData.items())
                                            {
                                                //std::cout << "mitreattack_k: " << mitreattack_k << "  mitreattack_v: " << mitreattack_v << std::endl;
                                                if(mitreattack_k == "technique_id" && !( mitreattack_v.get<std::string>().empty() ) )
                                                {
                                                    event_type_counts[mitreattack_v.get<std::string>()]++;
                                                    //std::cout << "mitreattack_k: " << mitreattack_k << "  event_type_counts[mitreattack_v.get<std::string>()]: " << event_type_counts[mitreattack_v.get<std::string>()] << std::endl;
                                                }
                                                    
                                                else if(mitreattack_k == "tactic_id" && !( mitreattack_v.get<std::string>().empty() ) )
                                                    event_type_counts[mitreattack_v.get<std::string>()]++;
                                                else if(mitreattack_k == "subtechnique_id" && !( mitreattack_v.get<std::string>().empty() ) )
                                                    event_type_counts[mitreattack_v.get<std::string>()]++;
                                            }
                                        }
                                    }
                                        
                                            
                                                
                                }
                            }

                            // Rule 벡터 추가
                            feature_vector.push_back(static_cast<double>(matched_rule_count));
                            feature_vector.push_back(static_cast<double>(matched_rule_severity_info_count));
                            feature_vector.push_back(static_cast<double>(matched_rule_severity_low_count));
                            feature_vector.push_back(static_cast<double>(matched_rule_severity_medium_count));
                            feature_vector.push_back(static_cast<double>(matched_rule_severity_high_count));
                            feature_vector.push_back(static_cast<double>(matched_rule_severity_critical_count));

                            // MITRE-ATTACK
                            // Reconnaissance (TA0043)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0043"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1595"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1595.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1595.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1595.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1592"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1592.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1592.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1592.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1592.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1598"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1598.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1598.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1598.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1598.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1597"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1597.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1597.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1596"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1596.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1596.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1596.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1596.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1596.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1593"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1593.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1593.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1593.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1594"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1589"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1589.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1589.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1589.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1590"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1590.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1590.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1590.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1590.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1590.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1590.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1591"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1591.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1591.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1591.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1591.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1600"]));

                            // Resource Development (TA0042)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0042"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1583"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1583.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1583.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1583.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1583.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1583.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1583.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1583.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1584"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1584.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1584.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1584.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1584.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1584.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1584.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1584.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1608"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1608.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1608.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1608.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1608.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1608.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1608.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1585"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1585.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1585.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1585.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1586"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1586.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1586.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1586.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1586.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1586.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1586.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1587"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1587.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1587.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1587.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1587.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1588"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1588.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1588.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1588.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1588.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1588.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1588.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1648"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1648.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1648.002"]));

                            // Initial Access (TA0001)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0001"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1078"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1078.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1078.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1078.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1078.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1133"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1189"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1190"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1195"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1195.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1195.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1195.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1566"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1566.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1566.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1566.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1566.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1655"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1199"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1200"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1650"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1651"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1091"]));

                            // Execution (TA0002)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0002"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1204"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1204.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1204.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1204.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1059"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1059.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1059.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1059.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1059.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1059.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1059.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1059.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1059.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1059.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1059.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1559"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1559.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1559.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1559.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1569"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1569.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1569.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1047"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1072"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1106"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1129"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1203"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.013"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.014"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1610"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1611"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1653"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1121"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1216"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.013"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.014"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1649"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1652"]));

                            // Persistence (TA0003)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0003"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1098"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1098.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1098.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1098.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1098.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1098.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1098.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1098.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.013"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.014"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.015"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1137"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1137.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1137.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1137.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1137.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1137.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1137.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1137.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1176"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.013"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.015"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.016"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.017"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1554"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1543"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1543.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1543.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1543.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1543.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1543.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1197"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1136"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1136.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1136.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1136.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1525"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1542"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1542.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1542.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1542.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1542.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1542.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1542.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1542.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1542.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1542.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1542.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.013"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.014"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1601"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1601.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1601.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1621"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1621.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1621.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1112"]));

                            // Privilege Escalation (TA0004)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0004"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1548"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1548.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1548.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1548.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1548.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1548.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1548.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.013"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.014"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1547.015"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.013"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.015"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.016"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1546.017"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1068"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.013"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1574.014"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1543"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1543.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1543.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1543.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1543.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1543.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.013"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.014"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1053.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1134"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1134.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1134.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1134.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1134.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1078.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1078.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1078.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1611"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1621"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1621.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1621.002"]));

                            // Defense Evasion (TA0005)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0005"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1562"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1562.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1562.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1562.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1562.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1562.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1562.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1562.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1562.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1562.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1562.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1562.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1070"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1070.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1070.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1070.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1070.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1070.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1070.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1070.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1070.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1070.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1211"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1027.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1140"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1548.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1553"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1553.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1553.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1553.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1553.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1553.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1553.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1553.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1564"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1564.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1564.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1564.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1564.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1564.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1564.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1564.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1564.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1564.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1564.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1599"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1599.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1599.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1599.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1036"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1036.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1036.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1036.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1036.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1036.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1036.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1036.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1036.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1036.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1480"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1480.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1221"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1622"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1620"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.013"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1055.014"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1202"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1205"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1207"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.013"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1218.014"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1222"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1222.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1222.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1497"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1497.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1497.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1497.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1614"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1629"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1629.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1629.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1629.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1629.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1654"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1014"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1078.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1078.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1078.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1112"]));

                            // Credential Access (TA0006)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0006"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1558"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1558.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1558.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1558.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1558.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1558.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1110"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1110.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1110.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1110.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1110.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1110.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1606"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1606.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1606.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1606.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1552"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1552.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1552.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1552.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1552.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1552.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1552.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1552.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1552.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1552.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1003.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1003.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1003.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1003.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1003.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1003.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1003.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1003.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1003.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1212"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555.010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555.011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1555.012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1556"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1556.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1556.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1556.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1556.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1556.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1556.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1556.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1557"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1557.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1557.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1557.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1505"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1505.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1505.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1505.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1505.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1528"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1539"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1069"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1621"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1621.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1621.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1649"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1653"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1056"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1056.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1056.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1056.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1056.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1111"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1187"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1040"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1081"]));

                            // Discovery (TA0007)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0007"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1087"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1087.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1087.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1087.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1087.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1069"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1069.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1069.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1069.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1482"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1217"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1010"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1615"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1083"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1033"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1135"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1518"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1518.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1518.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1057"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1012"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1592"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1046"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1018"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1201"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1049"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1082"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1614"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1614.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1538"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1016"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1016.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1016.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1040"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1120"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1526"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1526.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1526.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1526.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1526.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1526.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1526.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1526.007"]));

                            // Lateral Movement (TA0008)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0008"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1210"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1563"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1563.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1563.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1563.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1563.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1534"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1021"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1021.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1021.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1021.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1021.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1021.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1021.006"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1021.007"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1021.008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1021.009"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1570"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1550"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1550.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1550.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1550.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1550.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1091"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1105"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1558.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1651"]));

                            // Collection (TA0009)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0009"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1119"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1025"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1039"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1074"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1074.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1074.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1123"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1602"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1602.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1602.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1602.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1113"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1115"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1114"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1114.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1114.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1114.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1114.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1114.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1530"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1056"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1056.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1056.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1056.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1056.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1560"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1560.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1560.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1560.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1091"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1185"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1213"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1213.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1213.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1213.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1488"]));

                            // Command and Control (TA0011)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0011"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1071"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1071.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1071.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1071.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1071.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1105"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1573"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1573.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1573.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1573.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1092"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1095"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1104"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1571"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1572"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1090"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1090.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1090.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1090.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1090.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1090.005"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1001.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1001.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1001.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1132"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1132.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1132.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1008"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1219"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1094"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1102"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1102.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1102.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1102.003"]));

                            // Exfiltration (TA0010)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0010"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1048"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1048.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1048.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1048.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1048.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1020"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1020.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1020.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1020.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1567"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1567.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1567.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1011"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1011.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1011.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1041"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1052"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1052.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1537"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1030"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1022"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1029"]));

                            // Impact (TA0040)
                            feature_vector.push_back(static_cast<double>(event_type_counts["TA0040"]));

                            feature_vector.push_back(static_cast<double>(event_type_counts["T1485"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1486"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1489"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1490"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1491"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1491.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1491.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1531"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1565"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1565.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1565.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1565.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1561"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1561.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1561.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1561.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1495"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1496"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1498"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1499"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1499.001"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1499.002"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1499.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1499.004"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1529"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1657"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1558.003"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1647"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1492"]));
                            feature_vector.push_back(static_cast<double>(event_type_counts["T1570"]));
                }
                // [3/3] 이벤트 인텔리전스 정보 - 샘플 섹션
                void __get_sample_IntelligenceInfo(std::vector<double>& feature_vector, json& CompleteProcessNodeTree)
                {
                     //======================================================================
                    // [E] --- 인텔리전스 정보 ---
                    //======================================================================

                    // 기본값으로 사용할 빈 json 객체
                    const json empty_intel_object = json::object();
                    const auto& intelligences = CompleteProcessNodeTree.value("intelligences", empty_intel_object);

                    // --- 피처 1: 인텔리전스 카테고리 개수 ---
                    // "network", "file" 등 히트된 카테고리의 수
                    // .size()는 객체의 키-값 쌍의 개수를 반환합니다.
                    const unsigned long long category_count = intelligences.size();
                    feature_vector.push_back(static_cast<double>(category_count));


                    // --- 피처 2: 인텔리전스 '전체' 히트 개수 ---
                    // 모든 카테고리에 있는 인텔리전스 결과들의 총합
                    std::map<std::string, unsigned long long> category_map;
                    unsigned long long total_hit_count = 0;
                    if (intelligences.is_object()) {
                        for (const auto& [category, results_array] : intelligences.items()) {
                            unsigned long long array_size = results_array.size();
                            if (results_array.is_array()) {
                                total_hit_count += array_size;
                            }
                            category_map[category] = array_size;
                            std::cout << "category:::: " << category << std::endl;
                        }
                    }
                    feature_vector.push_back(static_cast<double>(total_hit_count));


                    // --- 피처 3: 인텔리전스 '카테고리 별' 히트 개수 ---
                    // 각 카테고리에 있는 인텔리전스 결과 총합
                    feature_vector.push_back(static_cast<double>(category_map["file"]));
                    feature_vector.push_back(static_cast<double>(category_map["network"]));
                    feature_vector.push_back(static_cast<double>(total_hit_count));
                }

            }; // class ProcessTreeManager
        }
    }
}

#endif