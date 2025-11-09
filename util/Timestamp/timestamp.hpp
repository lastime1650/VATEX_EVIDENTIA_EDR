#ifndef TIMESTAMP_H
#define TIMESTAMP_H

#include <linux/types.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>
#include <csignal>
#include <cerrno>
#include <cstring>   // strerror
#include <net/if.h>  // if_nametoindex
#include <ifaddrs.h>
#include <vector>
#include <thread> 
#include <tuple>
#include <unordered_map>
#include <cstdlib>
#include <chrono>    // C++11 chrono 라이브러리
#include <cstdint>   // uint64_t를 위해
#include <atomic>
#include <fmt/core.h>
#include <utility> 
#include <fstream>
#include <iomanip>
#include <fmt/chrono.h>
namespace EDR
{
    namespace Util
    {
        namespace timestamp
        {
            // Chrono -> __u64 기반 타임스탬프
            inline __u64 Get_Real_Timestamp()
            {
                auto now = std::chrono::system_clock::now();
                auto nano_since_epoch = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());
                return static_cast<__u64>(nano_since_epoch.count());
            }

            // nano to string
            inline std::string To_Nano_Iso8601(__u64 nano_since_epoch)
            {
                using namespace std::chrono;

                // 나노초 단위 타임포인트 생성
                auto tp = system_clock::time_point(nanoseconds(nano_since_epoch));

                // 초 단위까지만 자른 기준 시각
                auto tp_sec = time_point_cast<seconds>(tp);

                // 나노초 잔여 부분 계산
                auto nanos = nano_since_epoch % 1'000'000'000ULL;  // 10억 나노초 = 1초

                // ISO 8601 시각 문자열(나노초 9자리 포함)
                return fmt::format("{:%Y-%m-%dT%H:%M:%S}.{:09}Z", tp_sec, nanos);
            }

            // nano to timespec
            inline bool Get_timespec_by_Timestamp(__u64 input_timestamp, struct timespec* output)
            {
                if(!output)
                    return false;

                struct timespec ts;
                ts.tv_sec = input_timestamp / 1000000000ULL;        // 나노초를 초로 변환
                ts.tv_nsec = input_timestamp % 1000000000ULL;        // 남은 부분을 나노초로 변환

                *output = ts;

                return true;
            }
        }
    }
}

#endif