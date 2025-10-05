#ifndef API_HOOKER_HPP
#define API_HOOKER_HPP

#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <stdexcept>
#include <iostream> // ������ printf ���� ����

#include "API_HOOK_STRUCTS.hpp" // API_HOOK_INFO ����ü ����

namespace EDR
{
	namespace Util
	{
		namespace API_Hook
		{
			using API_HANDLER_PVOID = PVOID;

			class API_HOOK_CLASS
			{
			public:
				API_HOOK_CLASS() = default;
				~API_HOOK_CLASS() { Unhook_All(false); }

				/**
				 * @brief API ��ŷ�� �����մϴ�.
				 */
				BOOLEAN Init_Set_Hook(HMODULE hModule, const std::string& FunctionName, API_HANDLER_PVOID API_HANDLER)
				{
					if (!hModule || !API_HANDLER || HookInfo.count(API_HANDLER)) {
						return FALSE;
					}

					PVOID functionStub = GetProcAddress(hModule, FunctionName.c_str());
					if (!functionStub) {
						return FALSE;
					}

					PVOID target = functionStub;// ResolveJmpChain(functionStub);
					if (!target) return FALSE;

					printf("[Init_Set_Hook] \"%s\": %p (Stub) -> %p (Actual)\n", FunctionName.c_str(), functionStub, target);

					auto info = std::make_unique<API_HOOK_INFO>();
					info->FunctionName = FunctionName;
					info->TargetAddress = target;
					info->HookHandler = API_HANDLER;
#ifdef _WIN64
					info->PatchSize = 12;
#else
					info->PatchSize = 5;
#endif
					memcpy(info->OriginalBytes, target, info->PatchSize);

					// �̸� ������ ���� ( ��ġ �������� ��ŷ�� �ɸ��� �Ϳ� �̸����� )
					HookInfo[API_HANDLER] = std::move(info); // mutex�� �־ ���� ����

					if (!PatchFunction( *(HookInfo[API_HANDLER]) ))
					{
						HookInfo.erase(API_HANDLER); // ���н� ����
						return FALSE;
					}

					
					return TRUE;
				}

				/**
				 * @brief ��� ���� �����մϴ�.
				 */
				void Unhook_All(bool release_resources = false)
				{
					for (auto& pair : HookInfo) {
						// �Ҹ��ڿ��� ȣ��� �� �����Ƿ� ���� ���� ���� (�Ҹ��ڴ� �̹� ���� ������ ����)
						RestoreFunction(*(pair.second));
					}
					if (release_resources) {
						HookInfo.clear();
					}
				}

				/**
				 * @brief �ڵ鷯 ���ο��� ���� �Լ��� ȣ���մϴ�. (���� -> ȣ�� -> ����ŷ)
				 */
				template<typename Ret, typename... Args>
				Ret CallOriginal(API_HANDLER_PVOID handler_address, Args... args)
				{


					auto it = HookInfo.find(handler_address);
					if (it == HookInfo.end())
						throw std::runtime_error("[Hooker] Hook info not found!");

					API_HOOK_INFO& info = *(it->second);

					std::lock_guard<std::mutex> lock(info.mtx);
					RestoreFunction(info);

					using FnType = Ret(WINAPI*)(Args...);
					FnType pfnOriginal = (FnType)info.TargetAddress;

					if constexpr (std::is_void_v<Ret>) {
						pfnOriginal(args...);
						PatchFunction(info);
					}
					else {
						Ret result = pfnOriginal(args...);
						PatchFunction(info);
						return result;
					}
				}

			private:
				std::map<API_HANDLER_PVOID, std::unique_ptr<API_HOOK_INFO>> HookInfo;
				std::atomic<bool> is_finished_hook = false;

				// ���� JMP�� �ؼ��ϴ� ���� �Լ�
				PVOID ResolveJmpTarget(PVOID addr, bool is64bit)
				{
					BYTE* p = reinterpret_cast<BYTE*>(addr);

					// 1. Short jump (EB rel8)
					if (p[0] == 0xEB)
					{
						int8_t rel = static_cast<int8_t>(p[1]);
						BYTE* next = p + 2;
						return reinterpret_cast<PVOID>(next + rel);
				}

					// 2. Near jump (E9 rel32)
					if (p[0] == 0xE9)
					{
						int32_t rel = *reinterpret_cast<int32_t*>(p + 1);
						BYTE* next = p + 5;
						return reinterpret_cast<PVOID>(next + rel);
					}

					// 3. Indirect jump (FF /4) - 32��Ʈ
					if (!is64bit && p[0] == 0xFF && (p[1] & 0x38) == 0x20)
					{
						int32_t disp32 = *reinterpret_cast<int32_t*>(p + 2);
						BYTE* targetAddr = reinterpret_cast<BYTE*>(disp32); // ���� �ּ�
						DWORD dest = *reinterpret_cast<DWORD*>(targetAddr);
						return reinterpret_cast<PVOID>(dest);
					}

					// 4. Indirect jump (FF /4) - 64��Ʈ
					if (is64bit)
					{
						// REX ���� ���: FF /4
						if (p[0] == 0xFF && (p[1] & 0x38) == 0x20)
						{
							int32_t disp32 = *reinterpret_cast<int32_t*>(p + 2);
							BYTE* rip = p + 6; // FF + modrm + disp32 �� �� 6����Ʈ
							BYTE* memAddr = rip + disp32;
							return *reinterpret_cast<PVOID*>(memAddr);
						}

						// REX prefix ���� ���: 48 FF /4
						if ((p[0] & 0xF0) == 0x40 && p[1] == 0xFF && (p[2] & 0x38) == 0x20)
						{
							int32_t disp32 = *reinterpret_cast<int32_t*>(p + 3);
							BYTE* rip = p + 7; // 48 FF 25 + disp32 �� 7����Ʈ
							BYTE* memAddr = rip + disp32;
							return *reinterpret_cast<PVOID*>(memAddr);
						}
					}

					// JMP �ƴ�
					return nullptr;
			}

				// JMP ü���� ���󰡼� ���� �ּҸ� ��� �Լ�
				inline PVOID ResolveJmpChain(PVOID pFunctionStub)
				{
					PVOID currentAddr = pFunctionStub;
					for (int i = 0; i < 10; ++i) {
#ifdef _WIN64
						PVOID destination = ResolveJmpTarget(currentAddr, true);
#else
						PVOID destination = ResolveJmpTarget(currentAddr, false);
#endif
						if (destination == nullptr) {
							return currentAddr; // �� �̻� JMP�� �ƴϸ� ���� �ּ�
						}
						else {
							std::cout << "JMP stub �߰�" << std::endl;
						}
						currentAddr = destination;
					}
					return currentAddr; // �ʹ� ���� ü���� ���������
				}

				// �޸𸮸� JMP �ڵ�� ����� �Լ�
				inline BOOLEAN PatchFunction(API_HOOK_INFO& info)
				{
					DWORD oldProtect;
					if (!VirtualProtect(info.TargetAddress, info.PatchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
						return FALSE;
					}

#ifdef _WIN64
					BYTE patch[12] = { 0x48, 0xB8 }; // mov rax, addr
					*(uint64_t*)(patch + 2) = (uint64_t)info.HookHandler;
					patch[10] = 0xFF; patch[11] = 0xE0; // jmp rax
					memcpy(info.TargetAddress, patch, info.PatchSize);
#else
					BYTE patch[5] = { 0xE9 }; // jmp rel32
					int32_t relativeOffset = (int32_t)info.HookHandler - ((int32_t)info.TargetAddress + 5);
					*(int32_t*)(patch + 1) = relativeOffset;
					memcpy(info.TargetAddress, patch, info.PatchSize);
#endif
					VirtualProtect(info.TargetAddress, info.PatchSize, oldProtect, &oldProtect);
					return TRUE;
				}

				// �޸𸮸� ���� �ڵ�� �����ϴ� �Լ�
				inline void RestoreFunction(const API_HOOK_INFO& info)
				{
					if (!info.TargetAddress) return;

					DWORD oldProtect;
					if (VirtualProtect(info.TargetAddress, info.PatchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
						memcpy(info.TargetAddress, info.OriginalBytes, info.PatchSize);
						VirtualProtect(info.TargetAddress, info.PatchSize, oldProtect, &oldProtect);
					}
				}
			};
			extern API_HOOK_CLASS g_ApiHooker;
		}
	}
}

#endif