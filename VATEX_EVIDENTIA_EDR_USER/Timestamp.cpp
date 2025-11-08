#include "timestamp.hpp"

namespace EDR
{
    namespace Util
    {
        namespace timestamp
        {
            // Chrono -> __u64 기반 타임스탬프
            bool Get_Real_Timestamp(ULONG64* output)
            {
                if (!output)
                    return false;


                auto now = std::chrono::system_clock::now();
                auto nano_since_epoch = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());
                *output = static_cast<ULONG64>(nano_since_epoch.count());

                return true;
            }
            std::string To_Nano_Iso8601(unsigned long long nano_since_epoch)
            {

                using namespace std::chrono;

                // 1. 나노초 단위를 생성합니다.
                auto d = nanoseconds(nano_since_epoch);

                // 2. nanoseconds 타입을 system_clock::duration 타입으로 명시적으로 변환한 후,
                //    이를 사용하여 time_point를 생성합니다.
                auto tp = system_clock::time_point(duration_cast<system_clock::duration>(d));

                // 3. 초 단위와 나머지 나노초를 계산하는 것은 동일합니다.
                auto tp_sec = time_point_cast<seconds>(tp);
                auto nanos = nano_since_epoch % 1'000'000'000ULL;

                // 4. 포맷팅하여 반환합니다.
                // (컴파일러가 C++20 std::format을 지원하지 않는 경우, #include <fmt/chrono.h> 후 fmt::format으로 변경)
                return std::format("{:%Y-%m-%dT%H:%M:%S}.{:09}Z", tp_sec, nanos);
                /*
                using namespace std::chrono;

                // system_clock의 duration 단위로 변환
                auto tp = system_clock::time_point(duration_cast<system_clock::duration>(nanoseconds(nano_since_epoch)));

                // 초 단위까지만 자른 기준 시각
                auto tp_sec = time_point_cast<seconds>(tp);

                // 나노초 잔여 부분 계산
                auto nanos = nano_since_epoch % 1'000'000'000ULL;

                // ISO 8601 문자열 생성
                return fmt::format("{:%Y-%m-%dT%H:%M:%S}.{:09}Z", tp_sec, nanos);*/
            }

            // __u64 기반 타임스탬프 -> timespec 
            bool Get_timespec_by_Timestamp(ULONG64 input_timestamp, struct timespec* output)
            {
                if (!output)
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