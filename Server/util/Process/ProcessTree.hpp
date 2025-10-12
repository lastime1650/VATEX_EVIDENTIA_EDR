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

                class Event
                {
                    public:
                        Event(json event, Solution::Intelligence::Intellina& Intelligence) : jsonEvent(event), Intelligence(Intelligence)
                        {
                            // 이벤트 공통 필드 저장
                            this->AGENT_ID = jsonEvent["header"]["agentid"].get<std::string>();
                            this->session.SessionID = jsonEvent["header"]["sessionid"].get<std::string>();
                            this->session.Root_SessionID = jsonEvent["header"]["root_sessionid"].get<std::string>();
                            this->session.Parent_SessionID = jsonEvent["header"]["parent_sessionid"].get<std::string>();
                            this->timestamp = jsonEvent["header"]["nano_timestamp"].get<unsigned long long>();
                            this->os.Platform = jsonEvent["header"]["os"]["type"].get<std::string>();
                            this->os.Version = jsonEvent["header"]["os"]["version"].get<std::string>();
                        }
                        virtual ~Event() = default;

                        json get_event(){ return jsonEvent; }
                        json get_header(){ return jsonEvent["header"]; }
                        json get_body(){ return jsonEvent["body"]; }


                        virtual void send_to_intelligence() = 0;

                        bool append_intelligence(json& input_result)
                        {
                            if( !input_result.size() )
                                return false;

                            for (auto& [key, value] : input_result.items())
                            {
                                intelligence_response[key] = value;
                            }

                            return true;
                        }
                        bool output_intelligence(json& output)
                        {
                            /*
                                {
                                    "post": [ 
                                        {
                                            "intelligence module name A" : { ... }
                                        },
                                        {
                                            "intelligence module name B" : { ... }
                                        },,,
                                    ]
                                }
                            */
                            if(!intelligence_response.size())
                                return false;
                            
                            output["post"] = json::array();
                            for( auto& result : intelligence_response )
                                output["post"].push_back(
                                    {
                                        { result.first, result.second }
                                    }
                                );

                            return true;
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
                        


                        Solution::Intelligence::Intellina& Intelligence;
                        std::map<std::string, json> intelligence_response;

                    protected:
                        json jsonEvent;

                        

                };

                class ProcessCreateEvent : public Event
                {
                    public:
                        ProcessCreateEvent(json event, Solution::Intelligence::Intellina& Intelligence) : Event(event, Intelligence) 
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
                            SID = event["body"]["user"]["sid"].get<std::string>();
                            Username = event["body"]["user"]["username"].get<std::string>();
                            
                        }

                        std::string exe_path;
                        unsigned long long exe_size;
                        std::string exe_sha256;
                        std::string commandline;

                        unsigned long long ppid;
                        std::string parent_exe_path;
                        unsigned long long parent_exe_size;
                        std::string parent_exe_sha256;

                        std::string SID;
                        std::string Username;
                        

                        void send_to_intelligence() override
                        {
                            if( exe_sha256.length() )
                            {
                                json output = json::object();
                                // sha256
                                if( Intelligence.Query_file_sha256(
                                    exe_sha256,
                                    output
                                ) )
                                    append_intelligence(output);
                            }

                            if( parent_exe_sha256.length() )
                            {
                                json output = json::object();
                                // sha256
                                if( Intelligence.Query_file_sha256(
                                    parent_exe_sha256,
                                    output
                                ) )
                                    append_intelligence(output);
                                
                            }

                        }
                        
                };
                class ProcessTerminateEvent : public Event
                {
                    public:
                        ProcessTerminateEvent(json event, Solution::Intelligence::Intellina& Intelligence) : Event(event, Intelligence) 
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
                        FileSystemEvent(json event, Solution::Intelligence::Intellina& Intelligence) : Event(event, Intelligence) 
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
                                json output = json::object();
                                // sha256
                                if( Intelligence.Query_file_sha256(
                                    filesha256,
                                    output
                                ) )
                                    append_intelligence(output);
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
                        NetworkEvent(json event, Solution::Intelligence::Intellina& Intelligence) : Event(event, Intelligence) 
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
                            /*
                                Source
                            */
                            if(sourceip.length())
                            {
                                // body/network/sourceip ip조회
                                json output;
                                // Only ip
                                if( Intelligence.Query_network_only_ipv4(
                                    sourceip,
                                    output
                                ) )
                                    append_intelligence(output);
                                
                                if(sourceport)
                                {
                                    // ip with port
                                    if( Intelligence.Query_network_ipv4_and_port(
                                        sourceip,
                                        sourceport,
                                        output
                                    ) )
                                        append_intelligence(output);
                                }
                                
                            }

                             /*
                                Destination
                            */
                            if(destinationip.length())
                            {
                                // body/network/destinationip ip조회
                                json output;

                                // Only ip
                                if( Intelligence.Query_network_only_ipv4(
                                    destinationip,
                                    output
                                ) )
                                    append_intelligence(output);

                                if(destinationport)
                                {
                                    // ip with port
                                    if( Intelligence.Query_network_ipv4_and_port(
                                        destinationip,
                                        destinationport,
                                        output
                                    ) )
                                        append_intelligence(output);
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
                        API_Call_Event(json event, Solution::Intelligence::Intellina& Intelligence) : Event(event, Intelligence) 
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
                            ImageLoadEvent(json event, Solution::Intelligence::Intellina& Intelligence) : Event(event, Intelligence) 
                            {
                                filepath = event["body"]["imageload"]["filepath"].get<std::string>();
                                filesize = event["body"]["imageload"]["filesize"].get<unsigned long long>();
                                filesha256 = event["body"]["imageload"]["filesha256"].get<std::string>();
                            }
                            void send_to_intelligence() override
                            {
                                if( filesha256.length() >= 64 )
                                {
                                    json output = json::object();
                                    // sha256
                                    if( Intelligence.Query_file_sha256(
                                        filesha256,
                                        output
                                    ) )
                                        append_intelligence(output);
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
                            ProcessAccessEvent(json event, Solution::Intelligence::Intellina& Intelligence) : Event(event, Intelligence) 
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
                            RegistryEvent(json event, Solution::Intelligence::Intellina& Intelligence) : Event(event, Intelligence) 
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


                    
                }
                namespace linux
                {

                }
            }

            namespace node
            {

                // node struct
                struct ProcessTreeNode
                {
                    
                    unsigned long long nodeDepthIndex = 0;

                    std::string AGENT_ID;
                    bool is_alive = true; // 노드 만료여부 
                    struct
                    {
                        std::string SessionID;
                        std::string Root_SessionID;
                        std::string Parent_SessionID;
                    }session;
                    bool is_placeholder = true; // 자리 표시자 노드인지 여부 ( 속된 말로 땜빵 )
                    std::vector<std::shared_ptr<ProcessEvent::Event>> events; // 다양한 유형 이벤트와 헤더(에이전트, os등)

                    struct
                    {
                        // 이 seen 타임스탬프 값은 EDR서버 자체적으로 매기는 것
                        // 로그에서 ["header"]["nano_timestamp"] 값으로 Update
                        unsigned long long first_seen = 0; // first
                        unsigned long long last_seen = 0;  // recent -> (응용): 업데이트가 오래되면 만료처리 가능 ( 단, 프로세스 종료시에는 바로 만료 )
                    }seen;

                    std::vector<struct ProcessTreeNode> Child;


                    // 루트 노드 찾기 ( root SessionID 기반)
                    ProcessTreeNode* get_root_node(std::vector<ProcessTreeNode>& tree_roots)
                    {
                        // tree_roots: 에이전트 루트 노드 벡터
                        for (auto& node : tree_roots)
                        {
                            if (node.session.SessionID == session.Root_SessionID)
                                return &node;
                        }
                        return nullptr; // 루트 노드 못 찾음
                    }

                    // 자기 노드의 직계 부모를 찾는 함수
                    ProcessTreeNode* get_parent_node(
                        const std::vector<ProcessTreeNode>& tree_roots,
                        const std::string& parent_session_id = ""
                    )
                    {
                        // 부모 SessionID가 비어있으면 자기 노드의 Parent_SessionID 사용
                        std::string target_parent_id = parent_session_id.empty() ? session.Parent_SessionID : parent_session_id;
                        if (target_parent_id.empty())
                            return nullptr; // 루트 노드이므로 부모 없음 취급

                        for (auto& node : tree_roots)
                        {
                            if (node.session.SessionID == target_parent_id)
                                return const_cast<ProcessTreeNode*>(&node); // 부모 발견

                            // 자식 순회 재귀
                            if (!node.Child.empty())
                            {
                                if (auto parent = get_parent_node(node.Child, target_parent_id))
                                    return parent;
                            }
                        }
                        return nullptr; // 부모 못 찾음
                    }

                    // 노드 살아있는 것들 개수
                    unsigned int count_alive_nodes()
                    {
                        unsigned int count = is_alive ? 1 : 0;
                        for (auto& child : Child)
                            count += child.count_alive_nodes();
                        return count;
                    }

                    // 노드 깊이 최대값
                    unsigned int get_max_depth()
                    {
                        unsigned int max_depth = nodeDepthIndex;
                        for (auto& child : Child)
                            max_depth = std::max(max_depth, child.get_max_depth());
                        return max_depth;
                    }

                    // 현 노드를 기준으로 자식의 자식,, 모든 자식 노드 개수를 반환 
                    unsigned int get_all_child_count( )
                    {
                        unsigned int output_count = 0; 
                        for (auto& child : Child)
                        {
                            output_count += 1; // 자식 노드
                            output_count += child.get_all_child_count(); // 재귀
                        }
                        return output_count;
                    }


                    // 현 노드를 기준으로 자식 뿌리를 하나의 JSON으로 변환
                    bool to_jsonTree(json& output)
                    {
                        /*
                        [ Example ]
                            {
                                "AGENT_ID": "agent-001",
                                "is_alive": true,
                                "is_placeholder": false,
                                "nodeDepthIndex": 0,
                                "session": {
                                    "SessionID": "1000",
                                    "Root_SessionID": "1000",
                                    "Parent_SessionID": ""
                                },
                                "seen": {
                                    "first_seen": 1690000000,
                                    "last_seen": 1690005000
                                },
                                "events": [
                                    { "header": { ... }, "body": { ... } }
                                ],
                                "Child": [
                                    {
                                    "AGENT_ID": "agent-001",
                                    "is_alive": true,
                                    "is_placeholder": false,
                                    "nodeDepthIndex": 1,
                                    "session": {
                                        "SessionID": "1001",
                                        "Root_SessionID": "1000",
                                        "Parent_SessionID": "1000"
                                    },
                                    "seen": { "first_seen": 1690000100, "last_seen": 1690000200 },
                                    "events": [ { "header": { ... }, "body": { ... } } ],
                                    "Child": []
                                    }
                                ]
                            }
                        */
                        try
                        {
                            // 현재 노드 기본 정보 직렬화
                            output = {
                                {"AGENT_ID", AGENT_ID},
                                {"is_alive", is_alive},
                                {"is_placeholder", is_placeholder},
                                {"nodeDepthIndex", nodeDepthIndex},
                                {"session", {
                                    {"SessionID", session.SessionID},
                                    {"Root_SessionID", session.Root_SessionID},
                                    {"Parent_SessionID", session.Parent_SessionID}
                                }},
                                {"seen", {
                                    {"first_seen", seen.first_seen},
                                    {"last_seen", seen.last_seen}
                                }}
                            };

                            // 이벤트 목록 직렬화
                            json event_array = json::array();
                            for (auto& ev : events)
                            {
                                if (ev)
                                    event_array.push_back(ev->get_event());
                            }
                            output["events"] = event_array;

                            // 자식 노드 재귀 직렬화
                            json child_array = json::array();
                            for (auto& child : Child)
                            {
                                json child_json;
                                if (child.to_jsonTree(child_json))
                                {
                                    child_array.push_back(child_json);
                                }
                            }
                            output["Child"] = child_array;

                            return true;
                        }
                        catch ( std::exception& e)
                        {
                            return false;
                        }
                    }

                    // 자신의 노드를 기준으로, 하위 자식들에 대한 모든 events 를 하나로 old->new 순으로 정렬
                    std::vector<json> get_all_events_sorted_by_time()
                    {
                        // 1. 자신과 모든 자식 노드의 이벤트를 한 곳에 모읍니다.
                        std::vector<std::shared_ptr<ProcessEvent::Event>> all_events;
                        
                        // 재귀적으로 이벤트를 수집하는 람다 함수
                        std::function<void(ProcessTreeNode&)> collect_events =
                            [&](ProcessTreeNode& node) {
                            // 현재 노드의 이벤트를 all_events 벡터에 추가
                            all_events.insert(all_events.end(), node.events.begin(), node.events.end());

                            // 모든 자식 노드에 대해 재귀적으로 호출
                            for (auto& child : node.Child)
                            {
                                collect_events(child);
                            }
                        };

                        // 현재 노드(this)부터 시작하여 이벤트 수집
                        collect_events(*this);


                        // 2. 타임스탬프(old -> new)를 기준으로 이벤트를 정렬합니다.
                        std::sort(all_events.begin(), all_events.end(), 
                            [](const std::shared_ptr<ProcessEvent::Event>& a, const std::shared_ptr<ProcessEvent::Event>& b) {
                            // a의 타임스탬프가 b보다 작으면 true를 반환 (오름차순 정렬)
                            return a->timestamp < b->timestamp;
                        });


                        // 3. 정렬된 이벤트 포인터 목록을 JSON 객체 벡터로 변환하여 반환합니다.
                        std::vector<json> sorted_json_events;
                        for (const auto& ev : all_events)
                        {
                            if (ev) // 유효한 이벤트인지 확인
                            {
                                sorted_json_events.push_back(ev->get_event());
                            }
                        }

                        return sorted_json_events;
                    }

                    json Summary()
                    {
                        return {
                            
                            {"depth", get_max_depth()},
                            {"child_count", get_all_child_count()},
                            {"alive_count", count_alive_nodes()}

                        };
                    }

                };
            }

            namespace map
            {
                // map : key
                std::string AGENT_ID;

                // map : data
                std::vector< std::shared_ptr<EDR::Server::Util::ProcessEvent::Event> > EventNodes;
            }

            class ProcessTreeManager
            {
                public:
                    ProcessTreeManager() = default;
                    ~ProcessTreeManager() = default;

                    bool add_process_node( std::shared_ptr<ProcessEvent::Event> eventNode, node::ProcessTreeNode*& node_output )
                    {
                        // 1. Agent ID로 해당 에이전트의 트리(루트 노드 벡터)를 가져옵니다. 없으면 새로 생성됩니다.
                        auto& agent_tree = tree_map[eventNode->AGENT_ID];

                        // 2. 이벤트의 SessionID로 노드가 이미 존재하는지 찾습니다.
                        auto* target_node = _find_node_by_session_id(agent_tree, eventNode->session.SessionID);

                        // --- 시나리오 1: 노드가 아직 존재하지 않음 ---
                        if (!target_node)
                        {
                            // 새 노드를 생성하고 이벤트 정보로 기본값을 채웁니다.
                            node::ProcessTreeNode new_node;
                            new_node.AGENT_ID = eventNode->AGENT_ID;
                            new_node.session.SessionID = eventNode->session.SessionID;
                            new_node.session.Parent_SessionID = eventNode->session.Parent_SessionID;
                            new_node.session.Root_SessionID = eventNode->session.Root_SessionID;
                            new_node.seen.first_seen = eventNode->timestamp;
                            new_node.seen.last_seen = eventNode->timestamp;
                            new_node.events.push_back(eventNode);

                            // 이벤트 타입에 따라 is_alive 와 is_placeholder 상태를 결정합니다.
                            if (dynamic_cast<ProcessEvent::ProcessCreateEvent*>(eventNode.get()))
                            {
                                new_node.is_placeholder = false; // 생성 이벤트가 왔으므로 실제 노드임
                            }
                            if (dynamic_cast<ProcessEvent::ProcessTerminateEvent*>(eventNode.get()))
                            {
                                new_node.is_alive = false; // 생성되자마자 종료 이벤트가 온 경우
                            }

                            // 노드를 트리의 올바른 위치에 배치합니다.
                            _place_new_node(agent_tree, std::move(new_node));

                            // output
                            node_output = _find_node_by_session_id(agent_tree, eventNode->session.SessionID);
                        }
                        // --- 시나리오 2: 노드가 이미 존재함 ---
                        else
                        {
                            // 기존 노드에 이벤트를 추가하고 last_seen을 업데이트합니다.
                            target_node->events.push_back(eventNode);
                            target_node->seen.last_seen = std::max(target_node->seen.last_seen, eventNode->timestamp);

                            // 만약 기존 노드가 자리 표시자(placeholder)였고, 지금 ProcessCreate 이벤트가 도착했다면,
                            // 실제 노드로 전환하고 정보를 업데이트합니다.
                            if (target_node->is_placeholder && dynamic_cast<ProcessEvent::ProcessCreateEvent*>(eventNode.get()))
                            {
                                target_node->is_placeholder = false;
                                // ProcessCreate 이벤트를 이벤트 목록의 맨 앞으로 이동시켜 가독성을 높일 수 있습니다.
                                std::rotate(target_node->events.rbegin(), target_node->events.rbegin() + 1, target_node->events.rend());
                            }

                            // ProcessTerminate 이벤트인 경우 is_alive 상태를 false로 변경합니다.
                            if (dynamic_cast<ProcessEvent::ProcessTerminateEvent*>(eventNode.get()))
                            {
                                target_node->is_alive = false;
                            }

                            // output
                            node_output = target_node;
                        }
                        
                        return true;
                    }

                    /**
                     * @brief 특정 Agent ID를 가진 전체 프로세스 트리를 조회합니다.
                     * @param agent_id 조회할 에이전트 ID
                     * @param out_tree [out] 트리의 루트 노드 벡터에 대한 포인터
                     * @return 트리 존재 여부
                     */
                    bool get_tree_by_agentid(const std::string& agent_id, std::vector<node::ProcessTreeNode>** out_tree)
                    {
                        auto it = tree_map.find(agent_id);
                        if (it == tree_map.end())
                            return false;   

                        *out_tree = &it->second; 
                        return true;
                    }

                    // 특정 노드 와 그 자식 모두 제거 (clear)
                    bool Remove_Node( const std::string& agent_id, const std::string& session_id )
                    {
                        std::vector<node::ProcessTreeNode>* RootNode = nullptr;
                        if( !get_tree_by_agentid(agent_id, &RootNode) || !RootNode )
                            return false;
                        
                        /* 특정 에이전트의 TreeNode 루트 가져옴 */

                        // Session_id 자신노드와 자신노드의 모든 자식을 clear() 함
                        return _remove_tree_nodes(*RootNode, session_id);
                    }

                private:

                    /**
                     * @brief 새로 생성된 노드를 트리의 올바른 위치에 배치합니다.
                     * @param agent_tree 해당 에이전트의 전체 트리(루트 벡터)
                     * @param new_node 배치할 새로운 노드
                     */
                    void _place_new_node(std::vector<node::ProcessTreeNode>& agent_tree, node::ProcessTreeNode&& new_node)
                    {
                        // case 1: 이 노드가 루트 노드인 경우 (SessionID == Root_SessionID)
                        if (new_node.session.SessionID == new_node.session.Root_SessionID)
                        {
                            new_node.nodeDepthIndex = 0;
                            agent_tree.push_back(std::move(new_node));
                            return;
                        }

                        // case 2: 부모 노드를 찾아 자식으로 추가
                        auto* parent_node = _find_node_by_session_id(agent_tree, new_node.session.Parent_SessionID);
                        if (parent_node)
                        {
                            new_node.nodeDepthIndex = parent_node->nodeDepthIndex + 1;
                            parent_node->Child.push_back(std::move(new_node));
                            // 부모의 last_seen도 자식 이벤트 시간에 맞춰 업데이트
                            parent_node->seen.last_seen = std::max(parent_node->seen.last_seen, new_node.seen.last_seen);
                            return;
                        }

                        // case 3: 부모 노드를 찾지 못한 경우 (이벤트 순서 꼬임)
                        // 부모에 대한 자리 표시자(placeholder) 노드를 생성하고, 그 노드를 새로운 루트로 추가한 뒤,
                        // 현재 노드를 그 자식으로 연결합니다.
                        node::ProcessTreeNode placeholder_parent;
                        placeholder_parent.AGENT_ID = new_node.AGENT_ID;
                        placeholder_parent.session.SessionID = new_node.session.Parent_SessionID;
                        placeholder_parent.session.Root_SessionID = new_node.session.Root_SessionID;
                        // placeholder의 부모는 아직 모르므로 비워둡니다. 나중에 부모의 create 이벤트가 오면 채워질 수 있습니다.
                        placeholder_parent.seen.first_seen = new_node.seen.first_seen; // 자식의 타임스탬프를 따라감
                        placeholder_parent.seen.last_seen = new_node.seen.last_seen;
                        placeholder_parent.is_placeholder = true;
                        placeholder_parent.is_alive = true; // 부모는 일단 살아있다고 가정
                        
                        placeholder_parent.nodeDepthIndex = 0; // 임시로 루트가 됨
                        new_node.nodeDepthIndex = 1; // 자식이 됨
                        
                        placeholder_parent.Child.push_back(std::move(new_node));
                        agent_tree.push_back(std::move(placeholder_parent));
                    }

                    /**
                     * @brief 재귀적으로 Session ID와 일치하는 노드를 찾습니다.
                     * @param nodes 탐색할 노드 벡터
                     * @param session_id 찾을 세션 ID
                     * @return 찾은 노드의 포인터. 없으면 nullptr.
                     */
                    node::ProcessTreeNode* _find_node_by_session_id(std::vector<node::ProcessTreeNode>& nodes, const std::string& session_id)
                    {
                        for (auto& node : nodes)
                        {
                            if (node.session.SessionID == session_id)
                                return &node;
                            
                            if (auto found = _find_node_by_session_id(node.Child, session_id))
                                return found;
                        }
                        return nullptr;
                    }

                    bool _add_node_by_process_create(std::vector<node::ProcessTreeNode>& agent_tree,
                                                std::shared_ptr<ProcessEvent::ProcessCreateEvent> createEvent)
                    {
                        node::ProcessTreeNode new_node;
                        new_node.AGENT_ID = createEvent->AGENT_ID;
                        new_node.session.Parent_SessionID = createEvent->session.Parent_SessionID;
                        new_node.session.Root_SessionID = createEvent->session.Root_SessionID;
                        new_node.session.SessionID = createEvent->session.SessionID;

                        new_node.events.push_back(createEvent);
                        new_node.seen.first_seen = createEvent->timestamp;
                        new_node.seen.last_seen = createEvent->timestamp;

                        if (createEvent->session.Root_SessionID == createEvent->session.SessionID)
                        {
                            // 최상위 노드인 경우 
                            new_node.nodeDepthIndex = 0;
                            agent_tree.push_back(new_node);
                            return true;
                        }

                        if (auto parent_node = _find_node_by_session_id(agent_tree, createEvent->session.Parent_SessionID))
                        {
                            new_node.nodeDepthIndex = parent_node->nodeDepthIndex + 1;
                            parent_node->Child.push_back(new_node);
                            parent_node->seen.last_seen = createEvent->timestamp;
                            return true;
                        }

                        // 이도 저도 아닐 때 최상위 취급
                        new_node.nodeDepthIndex = 0;
                        agent_tree.push_back(new_node);
                        return true;
                    }

                    bool _mark_node_as_terminated(std::vector<node::ProcessTreeNode>& agent_tree,
                                                std::shared_ptr<ProcessEvent::ProcessTerminateEvent> termEvent)
                    {
                        if (auto target = _find_node_by_session_id(agent_tree, termEvent->session.SessionID))
                        {
                            target->is_alive = false;
                            target->seen.last_seen = termEvent->timestamp;
                            return true;
                        }
                        return false;
                    }

                    // 특정 노드 트리 삭제 ( 자식 포함 됨 ) - targeting -> SessionID
                    bool _remove_tree_nodes(std::vector<node::ProcessTreeNode>& nodes, std::string SessionID) {
                        
                        for (auto it = nodes.begin(); it != nodes.end(); /* nothing */) {
                            if (it->session.SessionID == SessionID) {
                                // 자식 노드 전체 삭제
                                it->Child.clear();

                                // 자신 제거
                                it = nodes.erase(it);

                                return true; // 삭제 완료 후 종료
                            } else {
                                // 자식 노드 재귀 탐색
                                if (_remove_tree_nodes(it->Child, SessionID)) {
                                    return true; // 삭제 완료 후 종료
                                }
                                ++it;
                            }
                        }
                        return false; // 찾지 못함
                    }

                    using TreeMap = std::map<std::string, std::vector<node::ProcessTreeNode>>;
                    TreeMap tree_map;
                    EDR::Util::Queue::Queue<json> CompleteProcessNodeTreeQueue; // 다양하게 뻗어있는 "std::shared_ptr<EDR::Server::Util::ProcessEvent::Event>"에서 추적 타임아웃 되었거나, 모두 관련 프로세스 노드가 종료된 경우 하나의 JSON으로 모으는 것
            };
        }
    }
}

#endif