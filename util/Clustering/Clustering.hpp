#ifndef CLUSTERING_HPP
#define CLUSTERING_HPP

#include <map>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <string>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>


#include "../Udp/Udp.hpp"

namespace EDR
{
    namespace Util
    {
        namespace Clustering
        {
            namespace Clustering_Global
            {
                #define MAXIMUM_CONNECT_NODES 30 
                #define MASTER_HEARTBEAT_TIMEOUT_SECONDS 10 
                #define SLAVE_RESPONSE_TIMEOUT_SECONDS 3 

                enum CMD
                {
                    Hello,          
                    Update,         
                    Unknown,        
                    PromoteToMaster,
                    Remove          
                };

                enum ClusteringNodeMode
                {
                    Master,
                    Slave
                };

                #pragma pack(push, 1)
                struct NodePacket
                {
                    uint32_t NodeId;
                    char ipv4[16];          
                    uint32_t node_server_port;
                    uint32_t Nodemode;      
                    int32_t priority;
                };
                #pragma pack(pop)

                struct ClusteringMappingMapElement
                {
                    unsigned int NodeId;
                    std::string ipv4;
                    unsigned long node_server_port;
                    ClusteringNodeMode Nodemode;
                    int priority = -1; 
                    mutable EDR::Util::Udp::UdpClient udp_client;
                    mutable std::chrono::steady_clock::time_point last_seen;

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
                          udp_client(ip, static_cast<int>(port)), 
                          last_seen(std::chrono::steady_clock::now())
                    {
                        if (with_udp_client_connect_try)
                            udp_client.Connect();
                    }

                    ~ClusteringMappingMapElement()
                    {
                        udp_client.Close();
                    }

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

                    ClusteringMappingMapElement& operator=(const ClusteringMappingMapElement& other)
                    {
                        if (this != &other)
                        {
                            NodeId = other.NodeId;
                            ipv4 = other.ipv4;
                            node_server_port = other.node_server_port;
                            Nodemode = other.Nodemode;
                            priority = other.priority;
                            udp_client = EDR::Util::Udp::UdpClient(other.ipv4, static_cast<int>(other.node_server_port));
                            last_seen = other.last_seen;
                        }
                        return *this;
                    }

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
                    unsigned int,               
                    ClusteringMappingMapElement 
                >;
            }

            class ClusteringNode
            {
            public:
                ClusteringNode(
                    const unsigned int& my_nodeid,
                    const std::string& my_ipv4,
                    const unsigned long& my_node_server_port = 8801,
                    const std::string& some_node_server_ip = "", 
                    const unsigned int& some_node_server_port = 0
                    ) : my_nodeid(my_nodeid),
                        my_ipv4(my_ipv4),
                        my_node_server_port(my_node_server_port),
                        my_udp_server(my_ipv4, my_node_server_port)
                {
                    if (!my_udp_server.Run(
                        [this](const std::string& client_ip, std::vector<unsigned char> buffer, const unsigned long long& size) {
                            this->UDP_RECEIVE_CALLBACK(client_ip, std::move(buffer), size);
                        }))
                    {
                        throw std::runtime_error("ClusteringNode -> my_udp_server.Run() Failed");
                    }

                    if (some_node_server_ip.empty() || some_node_server_port == 0)
                    {
                        my_NodeMode = Clustering_Global::ClusteringNodeMode::Master;
                        my_priority = 0;

                        std::cout << "Starting as MASTER Node. NodeId: " << my_nodeid << std::endl;

                        auto my_node_info = _make_Mapping_info_Element(
                            this->my_nodeid, this->my_ipv4, this->my_node_server_port,
                            this->my_priority, this->my_NodeMode
                        );
                        
                        std::lock_guard<std::mutex> lock(map_mutex);
                        my_MappingMap.emplace(this->my_nodeid, std::move(my_node_info));

                        _start_heartbeat_check_thread();
                    }
                    else
                    {
                        my_NodeMode = Clustering_Global::ClusteringNodeMode::Slave;
                        my_priority = -1;

                        std::cout << "Starting as SLAVE Node. NodeId: " << my_nodeid << ". Attempting to connect to " << some_node_server_ip << ":" << some_node_server_port << std::endl;
                        
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
                unsigned int my_nodeid;
                EDR::Util::Udp::UdpServer my_udp_server;
                Clustering_Global::ClusteringNodeMode my_NodeMode;
                int my_priority = -1;
                std::string my_ipv4;
                unsigned long my_node_server_port;
                Clustering_Global::ClusteringMappingMap my_MappingMap;
                mutable std::mutex map_mutex;
                std::atomic<bool> is_running = {true};
                std::thread heartbeat_thread;

                // ===== [수정] 사용자가 의도한 condition_variable 멤버 변수들 =====
                bool is_waiting_for_master = false;
                std::condition_variable hello_cv;
                std::mutex hello_mtx;
                // =============================================================

                Clustering_Global::ClusteringMappingMapElement _make_Mapping_info_Element(const unsigned int& NodeId, const std::string& ipv4, const unsigned long& port, const int& priority, const Clustering_Global::ClusteringNodeMode& NodeMode, bool connect_try = false)
                {
                    return Clustering_Global::ClusteringMappingMapElement(NodeId, ipv4, port, NodeMode, priority, connect_try);
                }

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
                        _processing_Update();
                    }
                    return removed;
                }
                
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

                std::optional<unsigned int> _get_lowest_priority_node_id(bool include_master = false) const
                {
                    std::lock_guard<std::mutex> lock(map_mutex);
                    std::optional<unsigned int> target_id;
                    int lowest_priority = -1;

                    for (const auto& [nodeid, element] : my_MappingMap) {
                        if (!include_master && element.priority == 0) continue;

                        if (!target_id.has_value() || element.priority < lowest_priority) {
                            lowest_priority = element.priority;
                            target_id = nodeid;
                        }
                    }
                    return target_id;
                }

                std::optional<unsigned int> _get_highest_priority_node_id() const
                {
                    std::lock_guard<std::mutex> lock(map_mutex);
                    std::optional<unsigned int> target_id;
                    int highest_priority = -2;

                    for (const auto& [nodeid, element] : my_MappingMap) {
                        if (!target_id.has_value() || element.priority > highest_priority) {
                            highest_priority = element.priority;
                            target_id = nodeid;
                        }
                    }
                    return target_id;
                }
                
                void _join_cluster(const std::string& target_ip, unsigned int target_port)
                {
                    EDR::Util::Udp::UdpClient client(target_ip, target_port);
                    if (!client.Connect()) {
                        std::cerr << "Failed to connect to " << target_ip << ":" << target_port << std::endl;
                        return;
                    }

                    auto my_info_vec = _make_Mapping_info_Element(my_nodeid, my_ipv4, my_node_server_port, -1, Clustering_Global::Slave).To_Vector_Data();

                    std::vector<unsigned char> buffer;
                    auto cmd = Clustering_Global::CMD::Unknown;
                    buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&cmd), reinterpret_cast<unsigned char*>(&cmd) + sizeof(cmd));
                    buffer.insert(buffer.end(), my_info_vec.begin(), my_info_vec.end());

                    client.Send(buffer);
                    std::cout << "Sent 'Unknown' command to join cluster." << std::endl;
                }

                void _elect_new_master(unsigned int old_master_id)
                {
                    std::cout << "Master " << old_master_id << " is down. Starting new master election." << std::endl;
                    
                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        my_MappingMap.erase(old_master_id);
                    }

                    auto new_master_candidate_id = _get_lowest_priority_node_id(false);

                    if (!new_master_candidate_id.has_value()) {
                        std::cout << "No other slaves found. Promoting myself to Master." << std::endl;
                        _promote_self_to_master();
                        return;
                    }

                    if (new_master_candidate_id.value() == my_nodeid) {
                        std::cout << "I am the next master candidate. Promoting myself." << std::endl;
                        _promote_self_to_master();
                    } else {
                        std::cout << "Node " << *new_master_candidate_id << " is the new master candidate. Sending promotion command." << std::endl;
                        
                        std::optional<Clustering_Global::ClusteringMappingMapElement> candidate_element_opt;
                        {
                            std::lock_guard<std::mutex> lock(map_mutex);
                            auto it = my_MappingMap.find(*new_master_candidate_id);
                            if (it != my_MappingMap.end()) {
                                candidate_element_opt.emplace(it->second);
                            }
                        }

                        if (!candidate_element_opt) {
                            std::cerr << "Election failed: Candidate node " << *new_master_candidate_id << " disappeared." << std::endl;
                            return;
                        }

                        auto& candidate_element = *candidate_element_opt;
                        
                        if(!candidate_element.udp_client.Connect()) {
                            std::cerr << "Failed to connect to new master candidate " << *new_master_candidate_id << std::endl;
                            return;
                        }

                        std::vector<unsigned char> buffer;
                        auto cmd = Clustering_Global::CMD::PromoteToMaster;
                        buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&cmd), reinterpret_cast<unsigned char*>(&cmd) + sizeof(cmd));
                        buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&old_master_id), reinterpret_cast<unsigned char*>(&old_master_id) + sizeof(old_master_id));
                        
                        candidate_element.udp_client.Send(buffer);
                    }
                }
                
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
                            auto my_info = _make_Mapping_info_Element(my_nodeid, my_ipv4, my_node_server_port, 0, Clustering_Global::Master);
                            my_MappingMap.emplace(my_nodeid, std::move(my_info));
                        }
                        
                        int current_priority = 1;
                        for (auto& pair : my_MappingMap) {
                            if (pair.first == my_nodeid) continue;
                            pair.second.priority = current_priority++;
                        }
                    }

                    std::cout << "Promotion to MASTER complete. Broadcasting updated map." << std::endl;
                    _processing_Update();
                    _start_heartbeat_check_thread();
                }

                void _processing_Hello()
                {
                    auto master_id_opt = _find_node_by_priority(0);
                    if (!master_id_opt) {
                        std::cerr << "Hello failed: Master not found in map." << std::endl;
                        return;
                    }
                    unsigned int master_id = *master_id_opt;

                    std::optional<Clustering_Global::ClusteringMappingMapElement> master_element_opt;
                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        auto it = my_MappingMap.find(master_id);
                        if (it != my_MappingMap.end()) {
                           master_element_opt.emplace(it->second);
                        }
                    }

                    if (!master_element_opt) {
                        std::cerr << "Hello failed: Master node " << master_id << " disappeared." << std::endl;
                        _elect_new_master(master_id);
                        return;
                    }
                    auto& master_element = *master_element_opt;

                    if (!master_element.udp_client.Connect()) {
                        std::cerr << "Hello failed: Could not connect to Master " << master_id << std::endl;
                        _elect_new_master(master_id);
                        return;
                    }

                    auto my_info_vec = my_MappingMap.at(my_nodeid).To_Vector_Data();
                    std::vector<unsigned char> buffer;
                    auto cmd = Clustering_Global::CMD::Hello;
                    buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&cmd), reinterpret_cast<unsigned char*>(&cmd) + sizeof(cmd));
                    buffer.insert(buffer.end(), my_info_vec.begin(), my_info_vec.end());

                    master_element.udp_client.Send(buffer);

                    // ===== [수정] 사용자가 의도한 condition_variable 대기 로직 =====
                    // Master응답 대기
                    std::unique_lock<std::mutex> lock(hello_mtx);
                    is_waiting_for_master = true;
                    if (hello_cv.wait_for(lock, std::chrono::seconds(SLAVE_RESPONSE_TIMEOUT_SECONDS), [this] { return !is_waiting_for_master; })) {
                        // is_waiting_for_master == false -> 정상 응답
                        std::cout << "Received 'Update' response from Master." << std::endl;
                    } else {
                        // is_waiting_for_master == true -> 응답 없음(실패)
                        std::cerr << "Timeout: No 'Update' response from Master " << master_id << ". Assuming master is down." << std::endl;
                        _elect_new_master(master_id);
                    }
                    // =============================================================
                }

                void _processing_Update()
                {
                    if (my_NodeMode != Clustering_Global::ClusteringNodeMode::Master) return;

                    std::vector<unsigned char> buffer;
                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        if (my_MappingMap.size() > MAXIMUM_CONNECT_NODES) {
                            std::cerr << "Error: Map size exceeds MAXIMUM_CONNECT_NODES" << std::endl;
                            return;
                        }

                        auto cmd = Clustering_Global::CMD::Update;
                        buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&cmd), reinterpret_cast<unsigned char*>(&cmd) + sizeof(cmd));

                        for (const auto& [nodeid, element] : my_MappingMap) {
                            auto raw_data = element.To_Vector_Data();
                            buffer.insert(buffer.end(), raw_data.begin(), raw_data.end());
                        }

                        if (buffer.size() > 1472) {
                            std::cerr << "Warning: Update packet size is large (" << buffer.size() << " bytes)." << std::endl;
                        }

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
                }
                
                void _check_heartbeats() {
                    while(is_running) {
                        std::this_thread::sleep_for(std::chrono::seconds(MASTER_HEARTBEAT_TIMEOUT_SECONDS));
                        if (!is_running) break;
                        if (my_NodeMode != Clustering_Global::ClusteringNodeMode::Master) continue;

                        std::vector<unsigned int> dead_nodes;
                        {
                            std::lock_guard<std::mutex> lock(map_mutex);
                            for(const auto& [id, element] : my_MappingMap) {
                                if (id == my_nodeid) continue;

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
                                Remove_MappingMap(node_id, false);
                            }
                            _processing_Update();
                        }
                    }
                }
                
                void _start_heartbeat_check_thread() {
                    if (heartbeat_thread.joinable()) {
                        return;
                    }
                    heartbeat_thread = std::thread(&ClusteringNode::_check_heartbeats, this);
                }

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
                            default: std::cerr << "Unknown CMD received: " << static_cast<int>(cmd) << std::endl; break;
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "Error in UDP_RECEIVE_CALLBACK: " << e.what() << '\n';
                    }
                }

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
                        if (my_MappingMap.count(my_nodeid)) {
                           my_priority = my_MappingMap.at(my_nodeid).priority;
                        }
                    }
                    std::cout << "[Slave] Received 'Update'. Map synchronized. My priority: " << my_priority << std::endl;

                    // ===== [수정] 사용자가 의도한 condition_variable notify 로직 =====
                    // Slave에서 Master응답을 대기 중이면 notify_one 처리
                    std::unique_lock<std::mutex> lock(hello_mtx);
                    if (is_waiting_for_master) {
                        is_waiting_for_master = false;
                        hello_cv.notify_one();
                    }
                    // =============================================================
                }

                void _handle_Hello(std::vector<unsigned char>& buffer, size_t index, size_t total_size) {
                    if (my_NodeMode != Clustering_Global::ClusteringNodeMode::Master) return;

                    const size_t packet_size = sizeof(Clustering_Global::NodePacket);
                    if (index + packet_size > total_size) return;

                    Clustering_Global::NodePacket np{};
                    std::memcpy(&np, buffer.data() + index, packet_size);

                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        auto it = my_MappingMap.find(np.NodeId);
                        if (it != my_MappingMap.end()) {
                            it->second.last_seen = std::chrono::steady_clock::now();
                        } else {
                            if (my_MappingMap.size() < MAXIMUM_CONNECT_NODES) {
                                auto highest_prio_id = _get_highest_priority_node_id();
                                int new_priority = highest_prio_id.has_value() ? my_MappingMap.at(*highest_prio_id).priority + 1 : 1;
                                
                                auto element = _make_Mapping_info_Element(
                                    np.NodeId, std::string(np.ipv4), np.node_server_port,
                                    new_priority, Clustering_Global::Slave);
                                
                                my_MappingMap.emplace(np.NodeId, std::move(element));
                                std::cout << "[Master] New node " << np.NodeId << " joined via 'Hello'. Assigned priority " << new_priority << std::endl;
                            }
                        }
                    }
                    _processing_Update();
                }

                void _handle_Unknown(std::vector<unsigned char>& buffer, size_t index, size_t total_size) {
                    const size_t packet_size = sizeof(Clustering_Global::NodePacket);
                    if (index + packet_size > total_size) return;

                    Clustering_Global::NodePacket np{};
                    std::memcpy(&np, buffer.data() + index, packet_size);
                    std::string ipv4_str(np.ipv4);

                    if (my_NodeMode == Clustering_Global::ClusteringNodeMode::Master) {
                        bool needs_broadcast = false;
                        {
                            std::lock_guard<std::mutex> lock(map_mutex);
                            if (my_MappingMap.count(np.NodeId) == 0 && my_MappingMap.size() < MAXIMUM_CONNECT_NODES) {
                                auto highest_prio_id = _get_highest_priority_node_id();
                                int new_priority = highest_prio_id.has_value() ? my_MappingMap.at(*highest_prio_id).priority + 1 : 1;
                                
                                auto element = _make_Mapping_info_Element(
                                    np.NodeId, ipv4_str, np.node_server_port, new_priority, Clustering_Global::Slave
                                );
                                my_MappingMap.emplace(np.NodeId, std::move(element));
                                std::cout << "[Master] New node " << np.NodeId << " joined via 'Unknown'. Assigned priority " << new_priority << std::endl;
                                needs_broadcast = true;
                            }
                        }
                        if (needs_broadcast) {
                            _processing_Update();
                        }

                    } else if (my_NodeMode == Clustering_Global::ClusteringNodeMode::Slave) {
                        auto master_id = _find_node_by_priority(0);
                        if (!master_id.has_value()) return;
                        
                        try {
                             std::lock_guard<std::mutex> lock(map_mutex);
                             auto& master_element = my_MappingMap.at(*master_id);
                             if (!master_element.udp_client.Connect()) return;
                             master_element.udp_client.Send(buffer);
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
                    
                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        my_MappingMap.erase(old_master_id);
                    }
                    
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