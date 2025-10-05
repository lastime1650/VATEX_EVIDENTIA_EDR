// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"

#include <iostream>
#include "Manager.hpp"


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // 한번만 실행되도록 static local variable 사용
        static bool initialized = false;
        if (!initialized)
        {
            initialized = true;
            std::cout << "DLL_PROCESS_ATTACH" << std::endl;

            static EDR::Manager::DLLManager DLL_AGENT;
            DLL_AGENT.Start();
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
