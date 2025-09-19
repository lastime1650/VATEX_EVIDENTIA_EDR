#include "timestamp.hpp"

namespace EDR
{
    namespace Util
    {
        namespace timestamp
        {
            // Chrono -> __u64 ��� Ÿ�ӽ�����
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

                // �� ����, ������ �и�
                auto sec = duration_cast<seconds>(nanoseconds(nano_since_epoch));
                auto ms = duration_cast<milliseconds>(nanoseconds(nano_since_epoch)).count() % 1000;

                // time_t ��ȯ
                std::time_t t = sec.count();
                std::tm tm{};
                #if defined(_WIN32)
                                gmtime_s(&tm, &t);  // Windows ���� �Լ�
                #else
                                gmtime_r(&t, &tm);  // POSIX
                #endif

                // fmt�� �̿��� ���
                return fmt::format("{:%Y-%m-%dT%H:%M:%S}.{:03}Z", tm, ms);
            }

            // __u64 ��� Ÿ�ӽ����� -> timespec 
            bool Get_timespec_by_Timestamp(ULONG64 input_timestamp, struct timespec* output)
            {
                if (!output)
                    return false;

                struct timespec ts;
                ts.tv_sec = input_timestamp / 1000000000ULL;        // �����ʸ� �ʷ� ��ȯ
                ts.tv_nsec = input_timestamp % 1000000000ULL;        // ���� �κ��� �����ʷ� ��ȯ

                *output = ts;

                return true;
            }
        }

    }
}