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
            std::string Timestamp_From_Nano(unsigned long long nano_since_epoch)
            {
                using namespace std::chrono;

                // 초 단위, 나노초 분리
                auto sec = duration_cast<seconds>(nanoseconds(nano_since_epoch));
                auto ms = duration_cast<milliseconds>(nanoseconds(nano_since_epoch)).count() % 1000;

                // time_t 변환
                std::time_t t = sec.count();
                std::tm tm{};
                #if defined(_WIN32)
                                gmtime_s(&tm, &t);  // Windows 안전 함수
                #else
                                gmtime_r(&t, &tm);  // POSIX
                #endif

                // fmt를 이용해 출력
                return fmt::format("{:%Y-%m-%dT%H:%M:%S}.{:03}Z", tm, ms);
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