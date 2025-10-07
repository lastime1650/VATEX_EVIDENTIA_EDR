#ifndef _PROCESSCREATION_RECEIVE_HPP
#define _PROCESSCREATION_RECEIVE_HPP

#include "../../../util/util.hpp"
#include "../__Parent/_ebpf_receive.hpp"

#include "fmt/format.h"

/*
    ebpf skels 
*/
extern "C" {
    #include "../../../../ebpf/ProcessCreation/processcreation.bpf.skel.h"
}

namespace EDR
{
    namespace Agent
    {
        namespace Event
        {
            namespace ProcessCreation_Event
            {
                extern "C" int processcreation______ebpf_ring_handle_event(EDR::Util::eBPF::RingBufferHandlerCTX::RingBufferHandlerCTX_s* ctx, EDR::Util::eBPF::structs::Process_Creation_event* data, size_t data_sz)
                {
                    if(!data)
                        return 0;
                    

                    EDR::Util::eBPF::queue::queue_s Q_struct;
                    Q_struct.type = data->Header.type;
                    Q_struct.timestamp = EDR::Util::timestamp::Get_Real_Timestamp();
                    Q_struct.data = new unsigned char[data_sz];
                    memcpy( Q_struct.data, (unsigned char*)data, data_sz);

                    /*
                        post -> ProcessCreation

                        후속 파일 SHA256을 위해 fd를 사전에 얻는다.
                    */
                    Q_struct.post.ProcessCreation.self_exe_file_fd = open(EDR::Util::Helper::reversePath(data->exe_file).c_str(), O_RDWR);
                    Q_struct.post.ProcessCreation.parent_exe_file_fd = open(EDR::Util::Helper::reversePath(data->parent_exe_file).c_str(), O_RDWR);
                    
                    //std::cout << "self_exe_file_fd -> " << Q_struct.post.ProcessCreation.self_exe_file_fd << " SHA256: " << EDR::Util::Helper::FD_to_SHA256(Q_struct.post.ProcessCreation.self_exe_file_fd) << std::endl;

                    ctx->Queue.put(Q_struct);
                    return 0;
                }

                class ProcessCreation : public EBPF_RECEIVE_PARENT
                {
                    public:
                        ProcessCreation( EDR::Util::eBPF::RingBufferHandlerCTX::RingBufferHandlerCTX_s ebpf_handle_ctx )
                        : EBPF_RECEIVE_PARENT(ebpf_handle_ctx)
                        {}
                        ~ProcessCreation(){ Stop(); }

                        bool Run() override
                        {
                            std::cout << "[ProcessCreation] Run() called " << std::endl;
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

                        struct processcreation_bpf *skel = nullptr;
                        ring_buffer* RingBuffer = nullptr;

                        bool _connect_to_ebpf( struct processcreation_bpf** out_skel, ring_buffer** out_RingBuffer )
                        {
                            struct processcreation_bpf* Skel_= nullptr;
                            ring_buffer* RingBuffer = nullptr;
                            // 1. 스켈레톤 오픈
                            Skel_ = processcreation_bpf__open_and_load();
                            if(!Skel_)
                                throw std::runtime_error("processcreation_bpf__open_and_load 실패");
                            // 2. RingBuffer 연결
                            RingBuffer = ring_buffer__new(bpf_map__fd(Skel_->maps.processcreation_ringbuffer), (ring_buffer_sample_fn)processcreation______ebpf_ring_handle_event, (void*)( (EDR::Util::eBPF::RingBufferHandlerCTX::RingBufferHandlerCTX_s*)&ebpf_handle_ctx), NULL);
                            if (!RingBuffer)
                                throw std::runtime_error("processcreation_bpf -> ring_buffer__new 실패");
                            // 3. Attach
                            int err = processcreation_bpf__attach(Skel_);
                            if(err)
                                throw std::runtime_error("processcreation_bpf -> processcreation_bpf__attach 실패 ->");

                            *out_skel = Skel_;
                            *out_RingBuffer = RingBuffer;

                            return true;
                        }

                        bool _run()
                        {
                            // 1. connect ebpf
                            try
                            {
                                bool status = _connect_to_ebpf(&skel, &RingBuffer);
                                if(!status)
                                    return false;
                                is_running = true;
                            }
                            catch(const std::exception& e)
                            {
                                std::cerr << e.what() << '\n';
                                return false;
                            }
                            std::cout << "ProcessCreation Run EBPF Connected" << std::endl;

                            is_running = true;
                            // 2. start polling multi-thread
                            RingBuff_Polling_thread = std::thread(
                                [this]()
                                {
                                    while(this->is_running)
                                    {
                                        ring_buffer__poll(
                                            this->RingBuffer,
                                            10
                                        );
                                    }
                                    std::cout << "ProcessCreation RingBuff_Polling_thread Stop" << std::endl;
                                }
                            );

                            return true;
                        }

                        bool _stop()
                        {
                            if(!skel || !RingBuffer)
                                return false;

                            is_running = false;
                            if(RingBuff_Polling_thread.joinable())
                                RingBuff_Polling_thread.join();

                            // Destroy
                            if(skel)
                                processcreation_bpf__destroy(skel);
                            
                            if(RingBuffer)
                                ring_buffer__free(RingBuffer);

                            return true;
                        }   
                    
                };
            }
            
        }
    }
}

#endif