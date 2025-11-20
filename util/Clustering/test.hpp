#ifndef CLUSTERING2_HPP
#define CLUSTERING2_HPP

#include "LengthBased.hpp" // 사용자 정의 헤더, 필요 시 포함
#include "../Udp/Udp.hpp"    // 사용자 정의 UDP 헤더, 필요 시 포함

#include <map>
#include <iostream>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <chrono>
#include <atomic>
#include <optional>
#include <cstring> // for memcpy, strncpy

/*
- CMD ->
    "Hello" Command: Slave -> Master (Heartbeat or initial contact)
    "Update" Command: Master -> Slaves (Broadcasts the entire cluster map)
    "Unknown" Command: New Node -> Any Node (Request to join the cluster)
    "PromoteToMaster" Command: Slave -> New Master Candidate (Orders promotion after old master failure)
    "Remove" Command: Master -> Slaves (Orders removal of a specific node)

- NodeTypes
    A. Master
        -> 1. MappingMapTable Permission: Read-Write
    B. Slave
        -> 1. MappingMapTable Permission: Read-Only (except when receiving 'Update')
*/

namespace EDR
{
    namespace Util
    {
        namespace Clustering
        {
            namespace Clustering_Global
            {
                #define MAXIMUM_CONNECT_NODES 30 // 최대 30개의 노드 수용 가능
                #define MASTER_HEARTBEAT_TIMEOUT_SECONDS 10 // Master가 Slave의 Heartbeat(Hello)를 기다리는 시간
                #define SLAVE_RESPONSE_TIMEOUT_SECONDS 3 // Slave가 Master의 응답(Update)을 기다리는 시간

                enum CMD
                {
                    Hello,           // Slave -> Master, 하트비트 또는 정보 갱신 요청
                    Update,          // Master -> Slaves, 클러스터 맵 정보 브로드캐스트
                    Unknown,         // New Node -> Any Node, 클러스터 참여 요청
                    PromoteToMaster, // Slave -> New Master Candidate, Master 승격 요청
                    Remove           // Master -> Slaves, 특정 노드 제거 요청
                };

                // 노드 모드
                enum ClusteringNodeMode
                {
                    Master,
                    Slave
                };

                #pragma pack(push, 1) // 1바이트 단위로 정렬
                struct NodePacket
                {
                    uint32_t NodeId;
                    char ipv4[16];           // null 포함
                    uint32_t node_server_port;
                    uint32_t Nodemode;       // enum ClusteringNodeMode
                    int32_t priority;
                };
                #pragma pack(pop)

                /* 클러스터링 매핑 맵 */
                // 매핑 데이터 요소
                struct ClusteringMappingMapElement
                {
                    unsigned int NodeId;
                    std::string ipv4;
                    unsigned long node_server_port;
                    ClusteringNodeMode Nodemode;
                    int priority = -1; // -1: Unknown, 0: Master, 1 or higher: Slave

                    // A. 내부적 사용
                    // A.1. UDP client
                    mutable EDR::Util::Udp::UdpClient udp_client;
                    // A.2. 마지막으로 Hello 신호를 받은 시간 (Master에서 사용)
                    mutable std::chrono::steady_clock::time_point last_seen;

                    // 생성자
                    ClusteringMappingMapElement(
                        unsigned int nodeId,
                        const std::string& ip,
                        unsigned long port,
                        ClusteringNodeMode mode,
                        int prio = -1,
                        bool with_udp_client_connect_try = false)
                        : NodeId(nodeId),
                          ipv4(ip),
                          node_server_port(port),
                          Nodemode(mode),
                          priority(prio),
                          udp_client(ip, static_cast<int>(port)), // UdpClient 생성자에 맞게 형변환
                          last_seen(std::chrono::steady_clock::now())
                    {
                        if (with_udp_client_connect_try)
                            udp_client.Connect();
                    }

                    // 소멸자
                    ~ClusteringMappingMapElement()
                    {
                        udp_client.Close(); // UDP 소켓 정리
                    }

                    // 복사 생성자 (mutable 멤버인 udp_client를 고려)
                    ClusteringMappingMapElement(const ClusteringMappingMapElement& other)
                        : NodeId(other.NodeId),
                          ipv4(other.ipv4),
                          node_server_port(other.node_server_port),
                          Nodemode(other.Nodemode),
                          priority(other.priority),
                          udp_client(other.ipv4, static_cast<int>(other.node_server_port)),
                          last_seen(other.last_seen)
                    {
                    }

                    // 복사 대입 연산자
                    ClusteringMappingMapElement& operator=(const ClusteringMappingMapElement& other)
                    {
                        if (this != &other)
                        {
                            NodeId = other.NodeId;
                            ipv4 = other.ipv4;
                            node_server_port = other.node_server_port;
                            Nodemode = other.Nodemode;
                            priority = other.priority;
                            // udp_client는 새로 생성하거나 기존 것을 재설정해야 합니다.
                            // 여기서는 간단하게 새로 생성하는 방식을 택합니다.
                            udp_client.Close();
                            udp_client = EDR::Util::Udp::UdpClient(other.ipv4, static_cast<int>(other.node_server_port));
                            last_seen = other.last_seen;
                        }
                        return *this;
                    }

                    // NodePacket을 직렬화하여 vector<unsigned char>로 반환
                    std::vector<unsigned char> To_Vector_Data() const
                    {
                        NodePacket np{};
                        np.NodeId = static_cast<uint32_t>(NodeId);
                        strncpy(np.ipv4, ipv4.c_str(), sizeof(np.ipv4) - 1);
                        np.ipv4[sizeof(np.ipv4) - 1] = '\0';
                        np.node_server_port = static_cast<uint32_t>(node_server_port);
                        np.Nodemode = static_cast<uint32_t>(Nodemode);
                        np.priority = static_cast<int32_t>(priority);

                        std::vector<unsigned char> vec(sizeof(np));
                        std::memcpy(vec.data(), &np, sizeof(np));
                        return vec;
                    }
                };

                using ClusteringMappingMap = std::map<
                    unsigned int,               // NodeId
                    ClusteringMappingMapElement // NodeData
                >;
            }

            class ClusteringNode
            {
            public:
                ClusteringNode(
                    const unsigned int& my_nodeid,
                    const std::string& my_ipv4,
                    const unsigned long& my_node_server_port = 8801,
                    const std::string& some_node_server_ip = "", // 접속할 다른 노드 IP (마스터일 수 있음)
                    const unsigned int& some_node_server_port = 0   // 접속할 다른 노드 포트
                    ) : my_nodeid(my_nodeid),
                        my_ipv4(my_ipv4),
                        my_node_server_port(my_node_server_port),
                        my_udp_server(my_ipv4, my_node_server_port),
                        is_running(true)
                {
                    // UDP 서버 실행 (콜백 함수 등록)
                    if (!my_udp_server.Run(
                        [this](const std::string& client_ip, std::vector<unsigned char> buffer, const unsigned long long& size) {
                            this->UDP_RECEIVE_CALLBACK(client_ip, std::move(buffer), size);
                        }))
                    {
                        throw std::runtime_error("ClusteringNode -> my_udp_server.Run() Failed");
                    }

                    // some_node 정보가 없으면, 스스로 Master가 됨
                    if (some_node_server_ip.empty() || some_node_server_port == 0)
                    {
                        // 자신이 Master가 된다.
                        my_NodeMode = Clustering_Global::ClusteringNodeMode::Master;
                        my_priority = 0; // Master의 우선순위는 0

                        std::cout << "Starting as MASTER Node. NodeId: " << my_nodeid << std::endl;

                        // 자신의 정보를 매핑 테이블에 추가
                        auto my_node_info = _make_Mapping_info_Element(
                            this->my_nodeid,
                            this->my_ipv4,
                            this->my_node_server_port,
                            this->my_priority,
                            this->my_NodeMode
                        );
                        
                        std::lock_guard<std::mutex> lock(map_mutex);
                        my_MappingMap.emplace(this->my_nodeid, std::move(my_node_info));

                        // 마스터는 주기적으로 Slave들의 하트비트를 체크하는 스레드를 실행
                        _start_heartbeat_check_thread();
                    }
                    else
                    {
                        // 다른 노드에 접속하여 클러스터 정보를 받는 Slave로 시작
                        my_NodeMode = Clustering_Global::ClusteringNodeMode::Slave;
                        my_priority = -1; // 아직 미정

                        std::cout << "Starting as SLAVE Node. NodeId: " << my_nodeid << ". Attempting to connect to " << some_node_server_ip << ":" << some_node_server_port << std::endl;
                        
                        // 클러스터 참여를 시도
                        _join_cluster(some_node_server_ip, some_node_server_port);
                    }
                }

                ~ClusteringNode()
                {
                    is_running = false;
                    if(heartbeat_thread.joinable()) {
                        heartbeat_thread.join();
                    }
                    my_udp_server.Stop();
                }

            private:
                // 멤버 변수
                unsigned int my_nodeid;
                EDR::Util::Udp::UdpServer my_udp_server;
                Clustering_Global::ClusteringNodeMode my_NodeMode;
                int my_priority = -1;
                std::string my_ipv4;
                unsigned long my_node_server_port;
                Clustering_Global::ClusteringMappingMap my_MappingMap;
                mutable std::mutex map_mutex;
                std::atomic<bool> is_running;
                std::thread heartbeat_thread;

                // Slave가 Master의 응답을 기다리기 위한 동기화 객체
                bool is_waiting_for_master_response = false;
                std::condition_variable response_cv;
                std::mutex response_mtx;

                //--- 비공개 멤버 함수 ---//

                // ClusteringMappingMapElement 객체를 생성하는 헬퍼 함수
                Clustering_Global::ClusteringMappingMapElement _make_Mapping_info_Element(const unsigned int& NodeId, const std::string& ipv4, const unsigned long& port, const int& priority, const Clustering_Global::ClusteringNodeMode& NodeMode, bool connect_try = false)
                {
                    return Clustering_Global::ClusteringMappingMapElement(NodeId, ipv4, port, NodeMode, priority, connect_try);
                }

                // 매핑 맵에 노드를 추가/수정 (Master 전용)
                bool Set_MappingMap(const unsigned int& NodeId, Clustering_Global::ClusteringMappingMapElement&& info_Element)
                {
                    if (my_NodeMode == Clustering_Global::ClusteringNodeMode::Slave)
                        return false; // Slave는 맵을 직접 수정할 수 없음

                    std::lock_guard<std::mutex> lock(map_mutex);
                    my_MappingMap.erase(NodeId);
                    my_MappingMap.emplace(NodeId, std::move(info_Element));
                    return true;
                }

                // 매핑 맵에서 노드를 제거하고, 변경사항을 전파할지 결정 (Master 전용)
                bool Remove_MappingMap(const unsigned int& NodeId, bool broadcast_changes = true)
                {
                    if (my_NodeMode == Clustering_Global::ClusteringNodeMode::Slave)
                        return false;

                    bool removed = false;
                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        if (my_MappingMap.erase(NodeId) > 0) {
                            removed = true;
                            std::cout << "[Master] Node " << NodeId << " removed from map." << std::endl;
                        }
                    }

                    if (removed && broadcast_changes) {
                        _processing_Update(); // 맵 변경 후 즉시 브로드캐스트
                    }
                    return removed;
                }
                
                // 지정된 우선순위를 가진 노드의 ID를 반환 (const 함수)
                std::optional<unsigned int> _find_node_by_priority(int priority) const
                {
                    std::lock_guard<std::mutex> lock(map_mutex);
                    for (const auto& [nodeid, element] : my_MappingMap) {
                        if (element.priority == priority) {
                            return nodeid;
                        }
                    }
                    return std::nullopt;
                }

                // 가장 낮은 우선순위(가장 작은 숫자)를 가진 노드의 ID 반환 (Master 포함/미포함)
                std::optional<unsigned int> _get_lowest_priority_node_id(bool include_master = false) const
                {
                    std::lock_guard<std::mutex> lock(map_mutex);
                    std::optional<unsigned int> target_id;
                    int lowest_priority = -1;

                    for (const auto& [nodeid, element] : my_MappingMap) {
                        if (!include_master && element.priority == 0) continue; // 마스터 제외

                        if (!target_id.has_value() || element.priority < lowest_priority) {
                            lowest_priority = element.priority;
                            target_id = nodeid;
                        }
                    }
                    return target_id;
                }

                // 가장 높은 우선순위(가장 큰 숫자)를 가진 노드의 ID 반환
                std::optional<unsigned int> _get_highest_priority_node_id() const
                {
                    std::lock_guard<std::mutex> lock(map_mutex);
                    std::optional<unsigned int> target_id;
                    int highest_priority = -2; // priority는 -1부터 시작하므로

                    for (const auto& [nodeid, element] : my_MappingMap) {
                        if (!target_id.has_value() || element.priority > highest_priority) {
                            highest_priority = element.priority;
                            target_id = nodeid;
                        }
                    }
                    return target_id;
                }
                
                // Slave가 처음 클러스터에 참여할 때 호출
                void _join_cluster(const std::string& target_ip, unsigned int target_port)
                {
                    EDR::Util::Udp::UdpClient client(target_ip, target_port);
                    if (!client.Connect()) {
                        std::cerr << "Failed to connect to " << target_ip << ":" << target_port << std::endl;
                        // 여기서 재시도 로직이나 예외 처리를 할 수 있음
                        return;
                    }

                    // 자신의 정보를 NodePacket으로 만듦
                    auto my_info_vec = _make_Mapping_info_Element(my_nodeid, my_ipv4, my_node_server_port, -1, Clustering_Global::Slave).To_Vector_Data();

                    // CMD + NodePacket 데이터
                    std::vector<unsigned char> buffer;
                    auto cmd = Clustering_Global::CMD::Unknown;
                    buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&cmd), reinterpret_cast<unsigned char*>(&cmd) + sizeof(cmd));
                    buffer.insert(buffer.end(), my_info_vec.begin(), my_info_vec.end());

                    client.Send(buffer);
                    std::cout << "Sent 'Unknown' command to join cluster." << std::endl;
                    // 응답은 UDP_RECEIVE_CALLBACK에서 비동기적으로 처리됨
                }

                // Master 장애 시 새로운 Master를 선출하고 승격시키는 프로세스
                void _elect_new_master(unsigned int old_master_id)
                {
                    std::cout << "Master " << old_master_id << " is down. Starting new master election." << std::endl;
                    
                    // 1. 기존 마스터를 내 맵에서 제거
                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        my_MappingMap.erase(old_master_id);
                    }

                    // 2. 새로운 마스터 후보 찾기 (우선순위가 가장 낮은 Slave)
                    auto new_master_candidate_id = _get_lowest_priority_node_id(false);

                    if (!new_master_candidate_id.has_value()) {
                        // 남은 슬레이브가 없음. 내가 마스터가 된다.
                        std::cout << "No other slaves found. Promoting myself to Master." << std::endl;
                        _promote_self_to_master();
                        return;
                    }

                    if (new_master_candidate_id.value() == my_nodeid) {
                        // 내가 새로운 마스터가 될 차례
                        std::cout << "I am the next master candidate. Promoting myself." << std::endl;
                        _promote_self_to_master();
                    } else {
                        // 다른 노드에게 마스터가 되라고 요청
                        std::cout << "Node " << *new_master_candidate_id << " is the new master candidate. Sending promotion command." << std::endl;
                        Clustering_Global::ClusteringMappingMapElement candidate_element;
                        {
                            std::lock_guard<std::mutex> lock(map_mutex);
                            candidate_element = my_MappingMap.at(*new_master_candidate_id);
                        }

                        if(!candidate_element.udp_client.Connect()) {
                            std::cerr << "Failed to connect to new master candidate " << *new_master_candidate_id << std::endl;
                            // 여기서 다음 후보를 찾는 로직 추가 가능
                            return;
                        }

                        // PromoteToMaster CMD + 실패한 마스터 ID 전송
                        std::vector<unsigned char> buffer;
                        auto cmd = Clustering_Global::CMD::PromoteToMaster;
                        buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&cmd), reinterpret_cast<unsigned char*>(&cmd) + sizeof(cmd));
                        buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&old_master_id), reinterpret_cast<unsigned char*>(&old_master_id) + sizeof(old_master_id));
                        
                        candidate_element.udp_client.Send(buffer);
                    }
                }
                
                // 스스로를 Master로 승격시키는 함수
                void _promote_self_to_master()
                {
                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        my_NodeMode = Clustering_Global::ClusteringNodeMode::Master;
                        my_priority = 0;

                        if (my_MappingMap.count(my_nodeid)) {
                            my_MappingMap.at(my_nodeid).Nodemode = Clustering_Global::ClusteringNodeMode::Master;
                            my_MappingMap.at(my_nodeid).priority = 0;
                        } else {
                            // 맵에 내 정보가 없는 경우 (이론상 발생하면 안됨)
                            auto my_info = _make_Mapping_info_Element(my_nodeid, my_ipv4, my_node_server_port, 0, Clustering_Global::Master);
                            my_MappingMap.emplace(my_nodeid, std::move(my_info));
                        }
                        
                        // 다른 노드들의 priority 재정렬 (선택적)
                        int current_priority = 1;
                        for (auto& [id, element] : my_MappingMap) {
                            if (id == my_nodeid) continue;
                            element.priority = current_priority++;
                        }
                    }

                    std::cout << "Promotion to MASTER complete. Broadcasting updated map." << std::endl;
                    _processing_Update(); // 변경된 맵 정보를 모두에게 전파
                    _start_heartbeat_check_thread(); // 마스터 역할 시작
                }

                // 주기적으로 하트비트를 보내는 기능 (Slave 전용 스레드에서 실행될 수 있음)
                void _processing_Hello()
                {
                    // 1. Master 노드 찾기
                    auto master_id = _find_node_by_priority(0);
                    if (!master_id.has_value()) {
                        std::cerr << "Hello failed: Master not found in map." << std::endl;
                        // 마스터가 없으면 선출 프로세스 시작
                        // _elect_new_master() 호출은 타임아웃 발생 시에만 하므로 여기서는 로그만 남김
                        return;
                    }

                    Clustering_Global::ClusteringMappingMapElement master_element;
                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        if(my_MappingMap.find(*master_id) == my_MappingMap.end()) return;
                        master_element = my_MappingMap.at(*master_id);
                    }

                    if (!master_element.udp_client.Connect()) {
                        std::cerr << "Hello failed: Could not connect to Master " << *master_id << std::endl;
                        _elect_new_master(*master_id); // 연결 실패 시 즉시 장애로 간주
                        return;
                    }

                    // 2. 내 정보 전송
                    auto my_info_vec = my_MappingMap.at(my_nodeid).To_Vector_Data();
                    std::vector<unsigned char> buffer;
                    auto cmd = Clustering_Global::CMD::Hello;
                    buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&cmd), reinterpret_cast<unsigned char*>(&cmd) + sizeof(cmd));
                    buffer.insert(buffer.end(), my_info_vec.begin(), my_info_vec.end());

                    master_element.udp_client.Send(buffer);

                    // 3. Master 응답 대기
                    std::unique_lock<std::mutex> lock(response_mtx);
                    is_waiting_for_master_response = true;
                    if (response_cv.wait_for(lock, std::chrono::seconds(SLAVE_RESPONSE_TIMEOUT_SECONDS), [this] { return !is_waiting_for_master_response; })) {
                        // 응답 정상 수신
                        // std::cout << "Received 'Update' response from Master." << std::endl;
                    } else {
                        // 타임아웃 발생
                        std::cerr << "Timeout: No 'Update' response from Master " << *master_id << ". Assuming master is down." << std::endl;
                        _elect_new_master(*master_id);
                    }
                }

                // 현재 맵 정보를 모든 노드에 브로드캐스트 (Master 전용)
                void _processing_Update()
                {
                    if (my_NodeMode != Clustering_Global::ClusteringNodeMode::Master) return;

                    std::lock_guard<std::mutex> lock(map_mutex);
                    if (my_MappingMap.size() > MAXIMUM_CONNECT_NODES) {
                        std::cerr << "Error: Map size exceeds MAXIMUM_CONNECT_NODES" << std::endl;
                        return;
                    }

                    // 1. 데이터 준비: CMD + 전체 맵 정보
                    std::vector<unsigned char> buffer;
                    auto cmd = Clustering_Global::CMD::Update;
                    buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&cmd), reinterpret_cast<unsigned char*>(&cmd) + sizeof(cmd));

                    for (const auto& [nodeid, element] : my_MappingMap) {
                        auto raw_data = element.To_Vector_Data();
                        buffer.insert(buffer.end(), raw_data.begin(), raw_data.end());
                    }

                    if (buffer.size() > 1472) { // 일반적인 UDP MTU 사이즈 고려
                        std::cerr << "Warning: Update packet size is large (" << buffer.size() << " bytes)." << std::endl;
                    }

                    // 2. 자신을 제외한 모든 노드에 브로드캐스트
                    for (const auto& [nodeid, element] : my_MappingMap) {
                        if (nodeid == my_nodeid) continue;
                        
                        if (!element.udp_client.Connect()) {
                             std::cerr << "Update failed: Could not connect to node " << nodeid << std::endl;
                             continue;
                        }

                        if (!element.udp_client.Send(buffer)) {
                            std::cerr << "Failed to send update to NodeId: " << nodeid << std::endl;
                        }
                    }
                     std::cout << "[Master] Broadcasted map update to " << my_MappingMap.size() - 1 << " slave(s)." << std::endl;
                }
                
                // Master가 주기적으로 Slave들의 상태를 체크하는 스레드 함수
                void _check_heartbeats() {
                    while(is_running) {
                        std::this_thread::sleep_for(std::chrono::seconds(MASTER_HEARTBEAT_TIMEOUT_SECONDS));
                        if (!is_running) break;

                        std::vector<unsigned int> dead_nodes;
                        {
                            std::lock_guard<std::mutex> lock(map_mutex);
                            for(const auto& [id, element] : my_MappingMap) {
                                if (id == my_nodeid) continue; // 자신은 체크 제외

                                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::steady_clock::now() - element.last_seen
                                ).count();
                                
                                if (elapsed > MASTER_HEARTBEAT_TIMEOUT_SECONDS) {
                                    dead_nodes.push_back(id);
                                }
                            }
                        }

                        if (!dead_nodes.empty()) {
                            std::cout << "[Master] Found " << dead_nodes.size() << " dead node(s) due to heartbeat timeout." << std::endl;
                            for(unsigned int node_id : dead_nodes) {
                                Remove_MappingMap(node_id, false); // 브로드캐스트는 한번에
                            }
                            _processing_Update(); // 변경사항 일괄 브로드캐스트
                        }
                    }
                }
                
                void _start_heartbeat_check_thread() {
                    if (heartbeat_thread.joinable()) {
                        is_running = false;
                        heartbeat_thread.join();
                    }
                    is_running = true;
                    heartbeat_thread = std::thread(&ClusteringNode::_check_heartbeats, this);
                }

                // 수신된 UDP 패킷을 처리하는 콜백 함수
                void UDP_RECEIVE_CALLBACK(const std::string& client_ipv4, std::vector<unsigned char> buffer, const unsigned long long& real_received_size)
                {
                    if (real_received_size < sizeof(Clustering_Global::CMD)) return;

                    try {
                        size_t current_index = 0;
                        Clustering_Global::CMD cmd;
                        std::memcpy(&cmd, buffer.data(), sizeof(cmd));
                        current_index += sizeof(cmd);

                        switch (cmd) {
                            case Clustering_Global::CMD::Update: _handle_Update(buffer, current_index, real_received_size); break;
                            case Clustering_Global::CMD::Hello: _handle_Hello(buffer, current_index, real_received_size); break;
                            case Clustering_Global::CMD::Unknown: _handle_Unknown(buffer, current_index, real_received_size); break;
                            case Clustering_Global::CMD::PromoteToMaster: _handle_PromoteToMaster(buffer, current_index, real_received_size); break;
                            case Clustering_Global::CMD::Remove: _handle_Remove(buffer, current_index, real_received_size); break;
                            default: std::cerr << "Unknown CMD received: " << cmd << std::endl; break;
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "Error in UDP_RECEIVE_CALLBACK: " << e.what() << '\n';
                    }
                }

                // 각 CMD에 대한 핸들러 함수들
                void _handle_Update(std::vector<unsigned char>& buffer, size_t index, size_t total_size) {
                    if (my_NodeMode != Clustering_Global::ClusteringNodeMode::Slave) return;

                    const size_t packet_size = sizeof(Clustering_Global::NodePacket);
                    Clustering_Global::ClusteringMappingMap new_map;

                    while (index + packet_size <= total_size) {
                        Clustering_Global::NodePacket np{};
                        std::memcpy(&np, buffer.data() + index, packet_size);
                        index += packet_size;

                        auto element = _make_Mapping_info_Element(
                            np.NodeId, std::string(np.ipv4), np.node_server_port,
                            np.priority, static_cast<Clustering_Global::ClusteringNodeMode>(np.Nodemode)
                        );
                        new_map.emplace(np.NodeId, std::move(element));
                    }
                    
                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        my_MappingMap = std::move(new_map);
                        my_priority = my_MappingMap.at(my_nodeid).priority; // 내 priority 갱신
                    }
                    std::cout << "[Slave] Received 'Update'. Map synchronized. My priority: " << my_priority << std::endl;

                    std::unique_lock<std::mutex> lock(response_mtx);
                    if (is_waiting_for_master_response) {
                        is_waiting_for_master_response = false;
                        response_cv.notify_one();
                    }
                }

                void _handle_Hello(std::vector<unsigned char>& buffer, size_t index, size_t total_size) {
                    if (my_NodeMode != Clustering_Global::ClusteringNodeMode::Master) return;

                    const size_t packet_size = sizeof(Clustering_Global::NodePacket);
                    if (index + packet_size > total_size) return;

                    Clustering_Global::NodePacket np{};
                    std::memcpy(&np, buffer.data() + index, packet_size);

                    bool needs_update = false;
                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        if (my_MappingMap.find(np.NodeId) != my_MappingMap.end()) {
                            // 기존 노드의 하트비트: last_seen 갱신
                            my_MappingMap.at(np.NodeId).last_seen = std::chrono::steady_clock::now();
                        } else {
                            // 맵에 없는 노드의 Hello: 새로운 노드로 취급
                            if (my_MappingMap.size() < MAXIMUM_CONNECT_NODES) {
                                auto highest_prio_id = _get_highest_priority_node_id();
                                int new_priority = highest_prio_id.has_value() ? my_MappingMap.at(*highest_prio_id).priority + 1 : 1;
                                
                                auto element = _make_Mapping_info_Element(
                                    np.NodeId, std::string(np.ipv4), np.node_server_port,
                                    new_priority, Clustering_Global::Slave);
                                
                                my_MappingMap.emplace(np.NodeId, std::move(element));
                                std::cout << "[Master] New node " << np.NodeId << " joined via 'Hello'. Assigned priority " << new_priority << std::endl;
                                needs_update = true;
                            }
                        }
                    }
                    // Hello에 대한 응답으로 항상 Update를 보내줌
                    _processing_Update();
                }

                void _handle_Unknown(std::vector<unsigned char>& buffer, size_t index, size_t total_size) {
                    const size_t packet_size = sizeof(Clustering_Global::NodePacket);
                    if (index + packet_size > total_size) return;

                    Clustering_Global::NodePacket np{};
                    std::memcpy(&np, buffer.data() + index, packet_size);
                    std::string ipv4_str(np.ipv4);

                    if (my_NodeMode == Clustering_Global::ClusteringNodeMode::Master) {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        if (my_MappingMap.size() >= MAXIMUM_CONNECT_NODES) return; // 꽉 찼으면 무시

                        auto highest_prio_id = _get_highest_priority_node_id();
                        int new_priority = highest_prio_id.has_value() ? my_MappingMap.at(*highest_prio_id).priority + 1 : 1;
                        
                        auto element = _make_Mapping_info_Element(
                            np.NodeId, ipv4_str, np.node_server_port, new_priority, Clustering_Global::Slave
                        );
                        my_MappingMap.emplace(np.NodeId, std::move(element));
                        
                        std::cout << "[Master] New node " << np.NodeId << " joined via 'Unknown'. Assigned priority " << new_priority << std::endl;
                        _processing_Update(); // 즉시 브로드캐스트

                    } else if (my_NodeMode == Clustering_Global::ClusteringNodeMode::Slave) {
                        // Master에게 프록시 역할
                        auto master_id = _find_node_by_priority(0);
                        if (!master_id.has_value()) return;
                        
                        try {
                            auto& master_element = my_MappingMap.at(*master_id);
                            if (!master_element.udp_client.Connect()) return;
                            master_element.udp_client.Send(buffer); // 받은 데이터 그대로 전달
                            std::cout << "[Slave] Proxied 'Unknown' request for " << np.NodeId << " to Master." << std::endl;
                        } catch(const std::out_of_range& e) {
                             std::cerr << "Proxy failed: Master not in map." << std::endl;
                        }
                    }
                }

                void _handle_PromoteToMaster(std::vector<unsigned char>& buffer, size_t index, size_t total_size) {
                    if (index + sizeof(unsigned int) > total_size) return;

                    unsigned int old_master_id;
                    std::memcpy(&old_master_id, buffer.data() + index, sizeof(old_master_id));

                    std::cout << "Received 'PromoteToMaster' command. Old master was " << old_master_id << std::endl;
                    
                    // 1. 맵에서 이전 마스터 제거
                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        my_MappingMap.erase(old_master_id);
                    }
                    
                    // 2. 스스로를 마스터로 승격
                    _promote_self_to_master();
                }

                void _handle_Remove(std::vector<unsigned char>& buffer, size_t index, size_t total_size) {
                    if (my_NodeMode != Clustering_Global::ClusteringNodeMode::Slave) return;
                    if (index + sizeof(unsigned int) > total_size) return;

                    unsigned int node_to_remove;
                    std::memcpy(&node_to_remove, buffer.data() + index, sizeof(node_to_remove));
                    
                    std::lock_guard<std::mutex> lock(map_mutex);
                    if (my_MappingMap.erase(node_to_remove) > 0) {
                        std::cout << "[Slave] Received 'Remove' command. Node " << node_to_remove << " removed from map." << std::endl;
                    }
                }
            };
        }
    }
}

#endif // CLUSTERING_HPP