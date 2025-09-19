#ifndef TIMESTAMP_H
#define TIMESTAMP_H

#define FMT_UNICODE 0
#include <Windows.h>
#include <iostream>
#include <string>
#include <chrono>
#include <fmt/core.h>
#include <fmt/chrono.h>
namespace EDR
{
    namespace Util
    {
        namespace timestamp
        {
            // Chrono -> __u64 기반 타임스탬프
            bool Get_Real_Timestamp(ULONG64* output);
            std::string Timestamp_From_Nano(ULONG64 nano_since_epoch);
            // __u64 기반 타임스탬프 -> timespec 
            bool Get_timespec_by_Timestamp(ULONG64 input_timestamp, struct timespec* output);
        }
    }
}

#endif