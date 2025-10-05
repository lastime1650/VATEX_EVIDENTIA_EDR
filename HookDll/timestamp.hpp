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
            inline ULONG64 Get_Real_Timestamp()
            {
                auto now = std::chrono::system_clock::now();
                auto nano_since_epoch = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());
                return static_cast<ULONG64>(nano_since_epoch.count());

            }
        }
    }
}

#endif