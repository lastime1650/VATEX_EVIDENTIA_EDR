#ifndef _PARENT_EBPF_RECEIVE_HPP
#define _PARENT_EBPF_RECEIVE_HPP

#include "../../../util/util.hpp"

namespace EDR
{
    namespace Agent
    {
        namespace Event
        {
            class EBPF_RECEIVE_PARENT
            {
                protected:
                    EBPF_RECEIVE_PARENT(EDR::Util::eBPF::RingBufferHandlerCTX::RingBufferHandlerCTX_s ebpf_handle_ctx)
                    : ebpf_handle_ctx(ebpf_handle_ctx)
                    {}
                    ~EBPF_RECEIVE_PARENT() = default ;

                    virtual bool Run() = 0;
                    virtual bool Stop() = 0;
                    
                    EDR::Util::eBPF::RingBufferHandlerCTX::RingBufferHandlerCTX_s ebpf_handle_ctx;
                    

                    
            };
        }
    }
}


#endif