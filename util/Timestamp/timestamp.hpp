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
            inline std::string Timestamp_From_Nano(__u64 nano_since_epoch)
            {
                auto tp = std::chrono::system_clock::time_point(std::chrono::nanoseconds(nano_since_epoch));

                // 1. 날짜와 시:분:초 부분을 포맷팅하기 위해 초 단위로 자릅니다.
                auto tp_sec = std::chrono::time_point_cast<std::chrono::seconds>(tp);

                // 2. 밀리초(millisecond) 부분만 따로 계산합니다.
                //    전체 나노초를 1,000,000으로 나누면 전체 밀리초가 되고,
                //    1000으로 나눈 나머지가 초 아래의 밀리초 부분이 됩니다.
                auto milliseconds = (nano_since_epoch / 1'000'000) % 1000;

                // 3. 두 부분을 합쳐서 최종 문자열을 만듭니다.
                //    - 첫 번째 {}: tp_sec를 Y-m-dTH:M:S 형식으로 포맷팅
                //    - 두 번째 {}: milliseconds를 3자리 숫자로, 비는 곳은 0으로 채워서 포맷팅 (예: 45 -> "045")
                return fmt::format("{:%Y-%m-%dT%H:%M:%S}.{:03}Z", tp_sec, milliseconds);
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