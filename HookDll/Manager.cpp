#include "pch.h"


#include "Manager.hpp"

#include "Suspends.hpp"

#include "API_Hooker.hpp"
#include "Ioctl.hpp"
#include "API_HOOK_Handlers.hpp"

//EDR::Util::API_Hook::API_HOOK_CLASS g_ApiHooker;
//EDR::IOCTL::IoctlSender g_IoctlSender;

namespace EDR
{
	namespace IOCTL
	{
		IoctlSender g_IoctlSender;
	}

	namespace Util
	{
		namespace API_Hook
		{
			API_HOOK_CLASS g_ApiHooker;

			

		}
	}

	namespace Manager
	{
		bool DLLManager::Start()
		{
			bool return_bool = false;
			/*
			if (!EDR::Util::Suspends::Suspend_Thread())
			{
				std::cout << "Suspend_Thread 실패" << std::endl;
				return false;
			}
			std::cout << "Suspend_Thread 성공" << std::endl;
			*/
			
			for (auto& hook : EDR::Util::API_Hook::Handlers::g_API_Hooks)
			{
				HMODULE hModule = GetModuleHandleA(hook.ModuleName);
				if (!hModule)
					continue; // 모듈이 로드된 것이 아니라면 Skip한다. 절대 새로 Load하면, 원본 프로세스의 행동 로그가 변질됨.

				std::cout << "[PRE]  DLL: " << hook.ModuleName  << "API: " << hook.FunctionName << std::endl;

				BOOLEAN status = EDR::Util::API_Hook::g_ApiHooker.Init_Set_Hook(hModule, hook.FunctionName, hook.Handler);
				
				std::cout << "DLL: " << hook.ModuleName << "API: " << hook.FunctionName << " Bool: " << ( status == TRUE ? 1 : 0 ) << " HookAddress: " << hook.Handler	 << std::endl;
			}
			
			
			return_bool = true;
		Cleanup:
			{
				//EDR::Util::Suspends::Resume_Threads();
				//std::cout << "Resume_Threads" << std::endl;
				return return_bool;
			}
			
		}
	}
}
