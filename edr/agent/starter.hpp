#ifndef EDR_AGENT_STARTER_HPP
#define EDR_AGENT_STARTER_HPP

#include "../util/util.hpp"

#include "event/logsender.hpp"

/*
    EVENTS EBPF CLASSES
*/
#include "event/ProcessCreation/ProcessCreation.hpp" // process
#include "event/Network/Network.hpp"                // network

namespace EDR
{
    namespace Agent
    {
        

        class EDRAgent
        {
            public:
                EDRAgent(
                    std::string& AGENT_ID,

                    std::string broker_ip, 
                    __u32 broker_port, 
                    std::string topic
                    
                )
                : AGENT_ID(AGENT_ID), 
                LogSender(
                    broker_ip,
                    broker_port,
                    topic,
                    AGENT_ID,
                    EDR::Util::Helper::hardware::get_sys_version()
                ),
                processcreation(
                    {
                        AGENT_ID,
                        GlobalProcessSession,
                        GlobalNetworkSession,
                        GlobalQueue
                    }
                ),
                network(
                    {
                        AGENT_ID,
                        GlobalProcessSession,
                        GlobalNetworkSession,
                        GlobalQueue
                    }
                )
                {}
                ~EDRAgent() = default;

                bool Run()
                {
                    if( !processcreation.Run())
                    {
                        std::cout << "[EDRAgent]{Failed} Run -> ProcessCreation Failed" << std::endl;
                        return false;
                    }
                    std::cout << "[EDRAgent]{Notice} Run -> ProcessCreation instance running" << std::endl;

                     if( !network.Run())
                    {
                        std::cout << "[EDRAgent]{Failed} Run -> network Failed" << std::endl;
                        return false;
                    }
                    std::cout << "[EDRAgent]{Notice} Run -> network instance running" << std::endl;
                    


                    is_running = true;


                    // thread
                    GlobalQueueProcessingThread = std::thread(
                        [this]()
                        {
                            

                            while(this->is_running)
                            {
                                std::string ProcessSessionId;
                                std::string RootProcessSessionId;
                                std::string ParentProcessSessionId;

                                auto Event = this->GlobalQueue.get();

                                switch (Event.type)
                                {
                                    case EDR::Util::eBPF::structs::event_type::Process_Terminate:
                                    case EDR::Util::eBPF::structs::event_type::Process_Exec:
                                    {
                                        auto* ProcessCreationLog = reinterpret_cast<EDR::Util::eBPF::structs::Process_Creation_event*>(Event.data);

                                        //std::cout << "[" << ( ProcessCreationLog->Header.type ==  EDR::Util::eBPF::structs::event_type::Process_fork ? "fork" : "exec" ) <<  EDR::Util::Helper::reversePath(ProcessCreationLog->exe_file) <<")PID: " << ProcessCreationLog->Header.pid << " - (" << EDR::Util::Helper::reversePath(ProcessCreationLog->parent_exe_file) << ")PPID: " << ProcessCreationLog->ppid << std::endl; 

                                        EDR::Util::Helper::reversePath(ProcessCreationLog->parent_exe_file);
                                        

                                        // sha256
                                        std::string self_exe_file_sha256 = "";
                                        std::string parent_exe_file_sha256 = "";
                                        if( Event.post.ProcessCreation.self_exe_file_fd)
                                        {
                                            self_exe_file_sha256 = EDR::Util::Helper::FD_to_SHA256(Event.post.ProcessCreation.self_exe_file_fd);
                                            close(Event.post.ProcessCreation.self_exe_file_fd);
                                        }
                                        if( Event.post.ProcessCreation.parent_exe_file_fd )
                                        {
                                            parent_exe_file_sha256 = EDR::Util::Helper::FD_to_SHA256(Event.post.ProcessCreation.parent_exe_file_fd);
                                            close(Event.post.ProcessCreation.parent_exe_file_fd);
                                        }
                                            
                                        
                                        if (Event.type == EDR::Util::eBPF::structs::event_type::Process_Exec)
                                        {
                                            if( !this->GlobalProcessSession.ProcessCreate(  
                                                ProcessCreationLog->Header.pid,
                                                ProcessCreationLog->ppid,
                                                ProcessSessionId,
                                                RootProcessSessionId,
                                                ParentProcessSessionId
                                            ) )
                                                break;

                                            this->LogSender.Send_ProcessCreate(
                                                ProcessCreationLog->Header.pid,
                                                Event.timestamp,
                                                RootProcessSessionId,
                                                ParentProcessSessionId,
                                                ProcessSessionId,
                                                ProcessCreationLog->ppid,
                                                ProcessCreationLog->Header.uid,
                                                ProcessCreationLog->Header.gid,

                                                EDR::Util::Helper::reversePath(ProcessCreationLog->exe_file),
                                                ProcessCreationLog->exe_file_size,
                                                self_exe_file_sha256,

                                                EDR::Util::Helper::reversePath(ProcessCreationLog->parent_exe_file),
                                                ProcessCreationLog->parent_exe_file_size,
                                                parent_exe_file_sha256,

                                                EDR::Util::Helper::forceCopyString( (unsigned char*)ProcessCreationLog->cmdline, ProcessCreationLog->cmdline_str_len )
                                                
                                            );
                                        }
                                        else if (Event.type == EDR::Util::eBPF::structs::event_type::Process_Terminate)
                                        {
                                            if( !this->GlobalProcessSession.AppendingEvent(  
                                                ProcessCreationLog->Header.pid,
                                                ProcessSessionId,
                                                RootProcessSessionId,
                                                ParentProcessSessionId
                                            ) )
                                                break;

                                            this->LogSender.Send_ProcessRemove(
                                                ProcessCreationLog->Header.pid,
                                                Event.timestamp,
                                                RootProcessSessionId,
                                                ParentProcessSessionId,
                                                ProcessSessionId
                                            );
                                        }
                                            

                                        break;
                                    }
                                    case EDR::Util::eBPF::structs::event_type::Network:
                                    {
                                        auto* NetworkLog = reinterpret_cast<EDR::Util::eBPF::structs::Network_event*>(Event.data);

                                        if( !this->GlobalProcessSession.AppendingEvent(  
                                            NetworkLog->Header.pid,
                                            ProcessSessionId,
                                            RootProcessSessionId,
                                            ParentProcessSessionId
                                        ) )
                                            break;

                                        EDR::Session::Network::NetworkSessionInfo NetworkSessioninfo;
                                        if( !this->GlobalNetworkSession.Get_NetworkSessionInfo(  
                                            NetworkLog->protocol, 
                                            NetworkLog->ipSrc, 
                                            NetworkLog->portSrc, 
                                            NetworkLog->ipDst, 
                                            NetworkLog->portDst, 
                                            NetworkSessioninfo
                                        ) )
                                            break;

                                        

                                        this->LogSender.Send_Network(
                                            NetworkLog->Header.pid,
                                            Event.timestamp,
                                            RootProcessSessionId,
                                            ParentProcessSessionId,
                                            ProcessSessionId,
                                            NetworkLog->ifindex,
                                            NetworkLog->protocol,
                                            NetworkLog->pkt_len,
                                            NetworkLog->ipSrc,
                                            NetworkLog->portSrc,
                                            NetworkLog->ipDst,
                                            NetworkLog->portDst,
                                            NetworkLog->is_INGRESS,
                                            NetworkSessioninfo.SessionID,
                                            NetworkSessioninfo.first_seen_nanotimestamp,
                                            NetworkSessioninfo.last_seen_nanotimestamp
                                        );

                                        break;
                                    }
                                    
                                }

                                delete[] Event.data;
                            }
                            this->is_running = false;
                        }
                    );

                    return true;
                }

            private:
                std::string AGENT_ID;
                bool is_running = false ;
                std::thread GlobalQueueProcessingThread;

                EDR::Agent::Event::LogSender LogSender;

                /*
                    Global with BPF
                */
                EDR::Session::Process::ProcessSession GlobalProcessSession;
                EDR::Session::Network::NetworkSession GlobalNetworkSession;
                EDR::Util::Queue::Queue<EDR::Util::eBPF::queue::queue_s> GlobalQueue;



                EDR::Agent::Event::ProcessCreation_Event::ProcessCreation processcreation;
                EDR::Agent::Event::Network_Event::Network network;
        };
    }
}

#endif