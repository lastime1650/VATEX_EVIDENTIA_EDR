#ifndef _NETWORK_RECEIVE_HPP
#define _NETWORK_RECEIVE_HPP

#include <set>

#include "../../../util/util.hpp"
#include "../__Parent/_ebpf_receive.hpp"

/*
    ebpf skels 
*/
extern "C" {
    #include "../../../../ebpf/Network/network.bpf.skel.h"
}

namespace EDR
{
    namespace Agent
    {
        namespace Event
        {
            namespace Network_Event
            {

                extern "C" int network______ebpf_ring_handle_event(EDR::Util::eBPF::RingBufferHandlerCTX::RingBufferHandlerCTX_s* ctx, EDR::Util::eBPF::structs::Network_event* data, size_t data_sz)
                {
                    if(!data)
                        return 0;

                    EDR::Util::eBPF::queue::queue_s Q_struct;
                    Q_struct.type = data->Header.type;
                    Q_struct.timestamp = EDR::Util::timestamp::Get_Real_Timestamp();
                    Q_struct.data = new unsigned char[data_sz];
                    memcpy( Q_struct.data, (unsigned char*)data, data_sz);
                    
                    ctx->Queue.put(Q_struct);

                    return 0;
                }

                class Network : public EBPF_RECEIVE_PARENT
                {
                    public:
                        Network( EDR::Util::eBPF::RingBufferHandlerCTX::RingBufferHandlerCTX_s ebpf_handle_ctx )
                        : EBPF_RECEIVE_PARENT(ebpf_handle_ctx)
                        {}
                        ~Network(){ Stop(); }

                        bool Run() override
                        {
                            std::cout << "[Network] Run() called " << std::endl;
                            if(is_running)
                                return false;
                            
                            return _run();
                        }

                        bool Stop() override
                        {
                            if(!is_running)
                                return false;

                            return _stop();
                        }
                        
                    private:
                        bool is_running = false;
                        std::thread RingBuff_Polling_thread;

                        struct BpfObjects {
                            struct network_bpf* skel = nullptr;
                            ring_buffer* RingBuffer = nullptr;
                        };
                        std::map<
                            int,                //ifindex
                            BpfObjects          //skel+ring_buffer struct
                        > tc_bpf_objects;

                        int map_fd = 0;


                        bool _set_tc_interface(int ifindex, struct network_bpf* skel)
                        {
                            // tc 어태치
                            std::cout << "1" << std::endl;
                            struct bpf_tc_hook tc_hook;
                            struct bpf_tc_opts opts;

                            memset(&tc_hook, 0, sizeof(struct bpf_tc_hook));
                            tc_hook.sz = sizeof(struct bpf_tc_hook);
                            tc_hook.ifindex = ifindex;
                            tc_hook.attach_point = BPF_TC_INGRESS;

                            memset(&opts, 0, sizeof(struct bpf_tc_opts));
                            opts.sz = sizeof(struct bpf_tc_opts);
                            opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress_prog);
                            opts.flags = BPF_TC_F_REPLACE;
                            opts.priority = 1; // 내 tc ebpf 가 "1순위" 호출하도록
                            
                            if ( bpf_tc_attach( &tc_hook, &opts ) != 0 )
                            {
                                std::cout << "(INGRESS) bpf_tc_attach 실패" << std::endl;
                                return false;
                            }
                                

                            // [1/2] EGRESS 설정
                            memset(&tc_hook, 0, sizeof(struct bpf_tc_hook));
                            tc_hook.sz = sizeof(struct bpf_tc_hook);
                            tc_hook.ifindex = ifindex;
                            tc_hook.attach_point = BPF_TC_EGRESS;

                            memset(&opts, 0, sizeof(struct bpf_tc_opts));
                            opts.sz = sizeof(struct bpf_tc_opts);
                            opts.prog_fd = bpf_program__fd(skel->progs.tc_egress_prog);
                            opts.flags = BPF_TC_F_REPLACE;
                            opts.priority = 1; // 내 tc ebpf 가 "1순위" 호출하도록

                            if ( bpf_tc_attach( &tc_hook, &opts ) != 0 )
                            {
                                std::cout << "(EGRESS) bpf_tc_attach 실패" << std::endl; 
                                return false;
                            }

                            return true;
                        }

                        bool _TC_setup()
                        {
                            struct ifaddrs *ifaddr, *ifa;
                            std::set<std::string> seen_ifnames;

                            if (getifaddrs(&ifaddr) == -1) {
                                perror("getifaddrs");
                                return false;
                            }

                            for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
                            {
                                if (ifa->ifa_name == NULL || strcmp(ifa->ifa_name, "lo") == 0) 
                                    continue;

                                std::string ifname(ifa->ifa_name);
                                if(seen_ifnames.count(ifname))
                                    continue;
                                seen_ifnames.insert(ifname);

                                std::cout << "Setting up TC eBPF for interface: " << ifname << std::endl;
                                unsigned int ifindex = if_nametoindex(ifa->ifa_name);
                                if (ifindex == 0) {
                                    perror("if_nametoindex");
                                    continue;
                                }

                                // 1. TC qdisc 설정
                                std::string cmd = "tc qdisc add dev " + ifname + " clsact 2>/dev/null";
                                system(cmd.c_str());

                                // --- 각 인터페이스에 대한 개별 eBPF 객체 생성 (기존 _connect_to_ebpf 로직 통합) ---
                                struct network_bpf* skel = nullptr;
                                ring_buffer* rb = nullptr;
                                int err = 0;
                                bool is_success_progs = false;

                                try {
                                    // 1.1. 스켈레톤 오픈 및 로드
                                    skel = network_bpf__open_and_load();
                                    if(!skel)
                                        throw std::runtime_error("network_bpf__open_and_load failed for " + ifname);

                                    is_success_progs =_set_tc_interface(ifindex, skel);
                                    if(!is_success_progs)
                                        throw std::runtime_error("_set_tc_interface failed for " + ifname);

                                    // 1.2. 링버퍼 연결
                                    rb = ring_buffer__new(bpf_map__fd(skel->maps.network_ringbuffer), (ring_buffer_sample_fn)network______ebpf_ring_handle_event, (void*)&ebpf_handle_ctx, NULL);
                                    if (!rb)
                                        throw std::runtime_error("ring_buffer__new failed for " + ifname);

                                    // 1.3. TC 프로그램 Attach (open/load 후 attach는 분리)
                                    err = network_bpf__attach(skel);
                                    if(err)
                                        throw std::runtime_error("network_bpf__attach failed for " + ifname);
                                    
                                    // 1.4. HASH MAP에 에이전트 PID 삽입
                                    int map_fd = bpf_map__fd(skel->maps.user_hash);
                                    if (map_fd < 0)
                                        throw std::runtime_error("bpf_map__fd for user_hash failed for " + ifname);

                                    uint64_t agent_pid = (uint64_t)getpid();
                                    uint8_t value = 1;
                                    err = bpf_map_update_elem(map_fd, &agent_pid, &value, BPF_ANY);
                                    if(err)
                                        throw std::runtime_error("bpf_map_update_elem failed for " + ifname);

                                    // 1.5. 성공적으로 생성된 객체들을 맵에 저장
                                    tc_bpf_objects[ifindex] = {skel, rb};
                                    std::cout << "Successfully set up eBPF for " << ifname << std::endl;

                                } catch (const std::exception& e) {
                                    std::cerr << "Error setting up " << ifname << ": " << e.what() << std::endl;
                                    // 실패 시 생성된 리소스 정리
                                    if (rb) ring_buffer__free(rb);
                                    if (skel) network_bpf__destroy(skel);
                                    continue; // 다음 인터페이스로 계속
                                }
                            }

                            freeifaddrs(ifaddr);

                            if (tc_bpf_objects.empty()) {
                                std::cerr << "No network interfaces were successfully set up." << std::endl;
                                return false;
                            }

                            return true;
                        }

                        bool _run()
                        {
                            try {
                                if (!_TC_setup()) {
                                    _stop_internal(); // 부분적으로 성공한 리소스가 있을 수 있으므로 정리
                                    return false;
                                }
                            } catch (const std::exception& e) {
                                std::cerr << "Exception during eBPF setup: " << e.what() << '\n';
                                _stop_internal();
                                return false;
                            }

                            std::cout << "Network eBPF setup complete. Starting polling thread." << std::endl;
                            is_running = true;

                            // 여러 링버퍼를 순차적으로 폴링하는 스레드 시작
                            RingBuff_Polling_thread = std::thread([this]() {
                                // 폴링할 링버퍼 목록을 미리 준비
                                std::vector<ring_buffer*> ring_buffers_to_poll;
                                for (auto const& [ifindex, objects] : this->tc_bpf_objects) {
                                    ring_buffers_to_poll.push_back(objects.RingBuffer);
                                }

                                while(this->is_running) {
                                    for (auto rb : ring_buffers_to_poll) {
                                        // non-blocking poll (timeout=0) 또는 짧은 timeout
                                        ring_buffer__poll(rb, 10); 
                                    }
                                    // 모든 링버퍼를 폴링한 후 잠시 대기하여 CPU 사용률을 낮춤
                                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                }
                                std::cout << "Network RingBuff_Polling_thread stopped." << std::endl;
                            });

                            return true;
                        }
                        
                        // 내부 정리 함수
                        void _stop_internal() {
                            for (auto const& [ifindex, objects] : tc_bpf_objects) {
                                if (objects.RingBuffer) ring_buffer__free(objects.RingBuffer);
                                if (objects.skel) network_bpf__destroy(objects.skel);
                            }
                            tc_bpf_objects.clear();
                        }

                        bool _stop()
                        {
                            if (!is_running) return false;

                            is_running = false;
                            if(RingBuff_Polling_thread.joinable())
                                RingBuff_Polling_thread.join();
                            
                            _stop_internal();
                            std::cout << "All network eBPF resources have been cleaned up." << std::endl;
                            
                            return true;
                        }


                        

                    
                    
                };

                
            }
            
        }
    }
}




#endif