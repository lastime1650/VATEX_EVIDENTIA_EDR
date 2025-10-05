#ifndef API_HOOK_STRUCTS_HPP
#define API_HOOK_STRUCTS_HPP

#include <Windows.h>
#include <string>
#include <mutex>

namespace EDR
{
    namespace Util
    {
        namespace API_Hook
        {
            struct API_HOOK_INFO
            {
                std::string  FunctionName;
                PVOID  TargetAddress;
                PVOID  HookHandler;
                SIZE_T PatchSize;
                BYTE   OriginalBytes[20]; // 원본 바이트 백업 (최대 20바이트)

                // 스레드 안전성을 위한 뮤텍스
                std::mutex mtx;
            };
        }
    }
}

#endif