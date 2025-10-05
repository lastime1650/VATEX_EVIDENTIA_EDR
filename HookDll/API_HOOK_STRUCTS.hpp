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
                BYTE   OriginalBytes[20]; // ���� ����Ʈ ��� (�ִ� 20����Ʈ)

                // ������ �������� ���� ���ؽ�
                std::mutex mtx;
            };
        }
    }
}

#endif