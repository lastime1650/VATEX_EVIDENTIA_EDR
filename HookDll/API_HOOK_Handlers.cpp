#include "pch.h"
/*
    원본 호출

    (1) API호출 -> (2)JUMP to Here -> (3)Allocated Tramp Memory Area 호출 -> (4)Execute(~ 14bytes) -> (5)Jump to Next in Orignal API Area{ after <<14bytes ~> | JUMPED by (5) | -> {here} >> ]

*/
#include "API_HOOK_Handlers.hpp"
#include "API_Hooker.hpp" // Hooker 클래스 정의
#include "Ioctl.hpp"      // LogSender 클래스 정의
#include "json.hpp"       // nlohmann::json
#include "timestamp.hpp"

#include <iostream>

using json = nlohmann::json;


// 네임스페이스 단축
using namespace EDR::Util::API_Hook;
using namespace EDR::IOCTL;


namespace Handlers = EDR::Util::API_Hook::Handlers;
namespace Helper = EDR::Util::API_Hook::Handlers::Helper;

//========================================================================================
//========================================================================================
//
//                                  NTDLL.DLL Handlers
//
//========================================================================================
//========================================================================================


extern "C" {

    // 1. Thread Manipulation
    NTSTATUS NTAPI Handlers::My_NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtSuspendThread, ThreadHandle, PreviousSuspendCount);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtSuspendThread"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(ThreadHandle)},
                {"PreviousSuspendCount_Out", (PreviousSuspendCount ? std::to_string(*PreviousSuspendCount) : "NULL")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtResumeThread, ThreadHandle, PreviousSuspendCount);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtResumeThread"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(ThreadHandle)},
                {"PreviousSuspendCount_Out", (PreviousSuspendCount ? std::to_string(*PreviousSuspendCount) : "NULL")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    // 2. Code Injection & Memory Manipulation
    NTSTATUS NTAPI Handlers::My_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtAllocateVirtualMemory, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtAllocateVirtualMemory"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"BaseAddress_Out", (BaseAddress ? Helper::PtrToString(*BaseAddress) : "NULL")},
                {"RegionSize", (RegionSize ? std::to_string(*RegionSize) : "NULL")},
                {"Protect", Helper::ProtectFlagsToString(Protect)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtFreeVirtualMemory, ProcessHandle, BaseAddress, RegionSize, FreeType);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtFreeVirtualMemory"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"BaseAddress", (BaseAddress ? Helper::PtrToString(*BaseAddress) : "NULL")},
                {"RegionSize", (RegionSize ? std::to_string(*RegionSize) : "NULL")},
                {"FreeType", Helper::DwordToHexString(FreeType)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtReadVirtualMemory, ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtReadVirtualMemory"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"BaseAddress", Helper::PtrToString(BaseAddress)},
                {"BufferSize", std::to_string(BufferSize)},
                {"BytesRead_Out", (NumberOfBytesRead ? std::to_string(*NumberOfBytesRead) : "NULL")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtWriteVirtualMemory, ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtWriteVirtualMemory"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"BaseAddress", Helper::PtrToString(BaseAddress)},
                {"BufferSize", std::to_string(BufferSize)},
                {"BytesWritten_Out", (NumberOfBytesWritten ? std::to_string(*NumberOfBytesWritten) : "NULL")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtProtectVirtualMemory, ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtProtectVirtualMemory"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"BaseAddress", (BaseAddress ? Helper::PtrToString(*BaseAddress) : "NULL")},
                {"RegionSize", (RegionSize ? std::to_string(*RegionSize) : "NULL")},
                {"NewProtect", Helper::ProtectFlagsToString(NewProtect)},
                {"OldProtect_Out", (OldProtect ? Helper::ProtectFlagsToString(*OldProtect) : "NULL")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtCreateSection, SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtCreateSection"},
            {"args", {
                {"ObjectName", Helper::ObjectAttributesToString(ObjectAttributes)},
                {"Protection", Helper::ProtectFlagsToString(SectionPageProtection)},
                {"Attributes", Helper::DwordToHexString(AllocationAttributes)},
                {"FileHandle", Helper::PtrToString(FileHandle)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtMapViewOfSection, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtMapViewOfSection"},
            {"args", {
                {"SectionHandle", Helper::PtrToString(SectionHandle)},
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"BaseAddress_Out", (BaseAddress ? Helper::PtrToString(*BaseAddress) : "NULL")},
                {"Protection", Helper::ProtectFlagsToString(Win32Protect)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtUnmapViewOfSection, ProcessHandle, BaseAddress);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtUnmapViewOfSection"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"BaseAddress", Helper::PtrToString(BaseAddress)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtQueueApcThread, ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtQueueApcThread"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(ThreadHandle)},
                {"ApcRoutine", Helper::PtrToString(ApcRoutine)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtGetContextThread, ThreadHandle, ThreadContext);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtGetContextThread"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(ThreadHandle)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
    {
        if (ThreadContext) {
            json pre_log = {
                {"dll", "ntdll.dll"}, {"function", "NtSetContextThread"}, {"stage", "pre-call"},
                {"args", {
                    {"ThreadHandle", Helper::PtrToString(ThreadHandle)},
    #ifdef _WIN64
                    {"NewRIP", Helper::Ulong64ToHexString(ThreadContext->Rip)}
    #else
                    { "NewEIP", Helper::DwordToHexString(ThreadContext->Eip) }
    #endif
                }}
            };
            g_IoctlSender.SendToQueue(pre_log.dump());
        }

        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtSetContextThread, ThreadHandle, ThreadContext);

        json post_log = {
            {"dll", "ntdll.dll"}, {"function", "NtSetContextThread"}, {"stage", "post-call"},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(post_log.dump());
        return status;
    }

    // 3. Privilege Escalation & Token Manipulation
    NTSTATUS NTAPI Handlers::My_NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtOpenProcessToken, ProcessHandle, DesiredAccess, TokenHandle);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtOpenProcessToken"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"DesiredAccess", Helper::DwordToHexString(DesiredAccess)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }


    NTSTATUS NTAPI Handlers::My_NtOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle)
    {

        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtOpenThreadToken, ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);

        json log = {
            {"dll", "ntdll.dll"},
            {"function", "NtOpenThreadToken"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(ThreadHandle)},
                {"DesiredAccess", Helper::DwordToHexString(DesiredAccess)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength)
    {
        std::string newStateStr = "[null]";
        if (NewState && NewState->PrivilegeCount > 0) {
            LUID_AND_ATTRIBUTES priv = NewState->Privileges[0];
            char name[256];
            DWORD nameLen = sizeof(name);
            if (LookupPrivilegeNameA(NULL, &priv.Luid, name, &nameLen)) {
                newStateStr = name;
            }
            else {
                newStateStr = "LUID:" + std::to_string(priv.Luid.LowPart);
            }
        }

        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtAdjustPrivilegesToken, TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtAdjustPrivilegesToken"},
            {"args", {
                {"TokenHandle", Helper::PtrToString(TokenHandle)},
                {"NewState", newStateStr}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtDuplicateToken, ExistingTokenHandle, DesiredAccess, ObjectAttributes, EffectiveOnly, TokenType, NewTokenHandle);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtDuplicateToken"},
            {"args", {
                {"ExistingTokenHandle", Helper::PtrToString(ExistingTokenHandle)},
                {"TokenType", (TokenType == TokenPrimary ? "TokenPrimary" : "TokenImpersonation")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtFilterToken(HANDLE ExistingTokenHandle, ULONG Flags, PVOID SidsToDisable, PVOID PrivilegesToDelete, PVOID RestrictedSids, PHANDLE NewTokenHandle)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtFilterToken, ExistingTokenHandle, Flags, SidsToDisable, PrivilegesToDelete, RestrictedSids, NewTokenHandle);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtFilterToken"},
            {"args", {
                {"TokenHandle", Helper::PtrToString(ExistingTokenHandle)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtImpersonateThread(HANDLE ServerThreadHandle, HANDLE ClientThreadHandle, PSECURITY_QUALITY_OF_SERVICE SecurityQos)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtImpersonateThread, ServerThreadHandle, ClientThreadHandle, SecurityQos);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtImpersonateThread"},
            {"args", {
                {"ServerThread", Helper::PtrToString(ServerThreadHandle)},
                {"ClientThread", Helper::PtrToString(ClientThreadHandle)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtImpersonateClientOfPort(HANDLE PortHandle, PVOID Message)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtImpersonateClientOfPort, PortHandle, Message);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtImpersonateClientOfPort"},
            {"args", {
                {"PortHandle", Helper::PtrToString(PortHandle)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    // 4. Persistence (Non-File)
    NTSTATUS NTAPI Handlers::My_NtLoadDriver(PUNICODE_STRING DriverServiceName)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtLoadDriver, DriverServiceName);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtLoadDriver"},
            {"args", {
                {"DriverServiceName", (DriverServiceName ? Helper::UnicodeStringToString(*DriverServiceName) : "[null]")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtUnloadDriver(PUNICODE_STRING DriverServiceName)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtUnloadDriver, DriverServiceName);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtUnloadDriver"},
            {"args", {
                {"DriverServiceName", (DriverServiceName ? Helper::UnicodeStringToString(*DriverServiceName) : "[null]")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtCreateWnfStateName(PVOID p1, PVOID p2, PVOID p3, PVOID p4, PVOID p5, PVOID p6, PVOID p7)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtCreateWnfStateName, p1, p2, p3, p4, p5, p6, p7);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtCreateWnfStateName"},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtUpdateWnfStateData(PVOID p1, PVOID p2, PVOID p3, PVOID p4, PVOID p5, PVOID p6)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtUpdateWnfStateData, p1, p2, p3, p4, p5, p6);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtUpdateWnfStateData"},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    // 5. Defense Evasion & Stealth
    NTSTATUS NTAPI Handlers::My_NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtSetInformationThread, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtSetInformationThread"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(ThreadHandle)},
                {"InfoClass", std::to_string(ThreadInformationClass)},
                {"IsHideFromDebugger", (ThreadInformationClass == 0x11) ? "TRUE" : "FALSE"}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtSetInformationProcess, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtSetInformationProcess"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"InfoClass", std::to_string(ProcessInformationClass)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtRemoveProcessDebug, ProcessHandle, DebugObjectHandle);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtRemoveProcessDebug"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"DebugObjectHandle", Helper::PtrToString(DebugObjectHandle)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtSetInformationDebugObject(HANDLE DebugObjectHandle, ULONG DebugObjectInformationClass, PVOID DebugInformation, ULONG DebugInformationLength, PULONG ReturnLength)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtSetInformationDebugObject, DebugObjectHandle, DebugObjectInformationClass, DebugInformation, DebugInformationLength, ReturnLength);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtSetInformationDebugObject"},
            {"args", {
                {"DebugObjectHandle", Helper::PtrToString(DebugObjectHandle)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtSystemDebugControl(DWORD ControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtSystemDebugControl, ControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtSystemDebugControl"},
            {"args", {
                {"ControlCode", std::to_string(ControlCode)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtClose(HANDLE Handle)
    {
        json pre_log = {
            {"dll", "ntdll.dll"}, {"function", "NtClose"}, {"stage", "pre-call"},
            {"args", {{"Handle", Helper::PtrToString(Handle)}}}
        };
        g_IoctlSender.SendToQueue(pre_log.dump());

        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtClose, Handle);

        json post_log = {
            {"dll", "ntdll.dll"}, {"function", "NtClose"}, {"stage", "post-call"},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(post_log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtDelayExecution, Alertable, DelayInterval);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtDelayExecution"},
            {"args", {
                {"Milliseconds", (DelayInterval ? std::to_string(abs(DelayInterval->QuadPart / 10000)) : "0")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    // 6. Discovery & Reconnaissance (Non-File)
    NTSTATUS NTAPI Handlers::My_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtQuerySystemInformation, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtQuerySystemInformation"},
            {"args", {
                {"InfoClass", std::to_string(SystemInformationClass)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtQueryInformationProcess, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtQueryInformationProcess"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"InfoClass", std::to_string(ProcessInformationClass)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, DWORD MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtQueryVirtualMemory, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtQueryVirtualMemory"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"BaseAddress", Helper::PtrToString(BaseAddress)},
                {"InfoClass", std::to_string(MemoryInformationClass)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtQueryObject, Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtQueryObject"},
            {"args", {
                {"Handle", Helper::PtrToString(Handle)},
                {"InfoClass", std::to_string(ObjectInformationClass)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtQuerySystemEnvironmentValue(PUNICODE_STRING VariableName, PWSTR Value, ULONG ValueLength, PULONG ReturnLength)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtQuerySystemEnvironmentValue, VariableName, Value, ValueLength, ReturnLength);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtQuerySystemEnvironmentValue"},
            {"args", {
                {"VariableName", (VariableName ? Helper::UnicodeStringToString(*VariableName) : "[null]")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_NtQuerySystemEnvironmentValueEx(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, PULONG ValueLength, PULONG Attributes)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_NtQuerySystemEnvironmentValueEx, VariableName, VendorGuid, Value, ValueLength, Attributes);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "NtQuerySystemEnvironmentValueEx"},
            {"args", {
                {"VariableName", (VariableName ? Helper::UnicodeStringToString(*VariableName) : "[null]")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    // 7. Module Loading & Dynamic API Resolving
    NTSTATUS NTAPI Handlers::My_LdrLoadDll(PWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_LdrLoadDll, DllPath, DllCharacteristics, DllName, DllHandle);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "LdrLoadDll"},
            {"args", {
                {"DllName", (DllName ? Helper::UnicodeStringToString(*DllName) : "[null]")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_LdrGetProcedureAddress(PVOID DllHandle, PSTRING ProcedureName, ULONG ProcedureNumber, PVOID* ProcedureAddress)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_LdrGetProcedureAddress, DllHandle, ProcedureName, ProcedureNumber, ProcedureAddress);

        json log = {
            {"dll", "ntdll.dll"}, {"function", "LdrGetProcedureAddress"},
            {"args", {
                {"DllHandle", Helper::PtrToString(DllHandle)},
                {"ProcedureName", (ProcedureName && ProcedureName->Buffer ? Helper::AstrToString(ProcedureName->Buffer) : "byOrdinal")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

} // extern "C"

//========================================================================================
//========================================================================================
//
//                                 KERNEL32.DLL Handlers
//
//========================================================================================
//========================================================================================

extern "C" {

    // 1. Execution
    BOOL WINAPI Handlers::My_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CreateProcessA, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CreateProcessA"},
            {"args", {
                {"ApplicationName", Helper::AstrToString(lpApplicationName)},
                {"CommandLine", Helper::AstrToString(lpCommandLine)},
                {"CreationFlags", Helper::CreationFlagsToString(dwCreationFlags)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        if (result) {
            log["result_info"] = {
                {"ProcessID", lpProcessInformation->dwProcessId},
                {"ThreadID", lpProcessInformation->dwThreadId}
            };
        }
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CreateProcessW, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CreateProcessW"},
            {"args", {
                {"ApplicationName", Helper::WstrToString(lpApplicationName)},
                {"CommandLine", Helper::WstrToString(lpCommandLine)},
                {"CreationFlags", Helper::CreationFlagsToString(dwCreationFlags)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        if (result) {
            log["result_info"] = {
                {"ProcessID", lpProcessInformation->dwProcessId},
                {"ThreadID", lpProcessInformation->dwThreadId}
            };
        }
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_CreateProcessAsUserA(HANDLE hToken, LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CreateProcessAsUserA, hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CreateProcessAsUserA"},
            {"args", {
                {"Token", Helper::PtrToString(hToken)},
                {"ApplicationName", Helper::AstrToString(lpApplicationName)},
                {"CommandLine", Helper::AstrToString(lpCommandLine)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_CreateProcessAsUserW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CreateProcessAsUserW, hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CreateProcessAsUserW"},
            {"args", {
                {"Token", Helper::PtrToString(hToken)},
                {"ApplicationName", Helper::WstrToString(lpApplicationName)},
                {"CommandLine", Helper::WstrToString(lpCommandLine)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HANDLE WINAPI Handlers::My_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
    {
        HANDLE hThread = g_ApiHooker.CallOriginal<HANDLE>((PVOID)My_CreateRemoteThread, hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CreateRemoteThread"},
            {"args", {
                {"TargetProcess", Helper::PtrToString(hProcess)},
                {"StartAddress", Helper::PtrToString(lpStartAddress)}
            }},
            {"return", Helper::PtrToString(hThread)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return hThread;
    }

    HANDLE WINAPI Handlers::My_CreateRemoteThreadEx(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId)
    {
        HANDLE hThread = g_ApiHooker.CallOriginal<HANDLE>((PVOID)My_CreateRemoteThreadEx, hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CreateRemoteThreadEx"},
            {"args", {
                {"TargetProcess", Helper::PtrToString(hProcess)},
                {"StartAddress", Helper::PtrToString(lpStartAddress)}
            }},
            {"return", Helper::PtrToString(hThread)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return hThread;
    }

    UINT WINAPI Handlers::My_WinExec(LPCSTR lpCmdLine, UINT uCmdShow)
    {
        UINT result = g_ApiHooker.CallOriginal<UINT>((PVOID)My_WinExec, lpCmdLine, uCmdShow);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "WinExec"},
            {"args", {
                {"CommandLine", Helper::AstrToString(lpCmdLine)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_QueueUserWorkItem(LPTHREAD_START_ROUTINE Function, PVOID Context, ULONG Flags)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_QueueUserWorkItem, Function, Context, Flags);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "QueueUserWorkItem"},
            {"args", {
                {"Function", Helper::PtrToString(Function)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_CreateTimerQueueTimer(PHANDLE phNewTimer, HANDLE TimerQueue, WAITORTIMERCALLBACK Callback, PVOID Parameter, DWORD DueTime, DWORD Period, ULONG Flags)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CreateTimerQueueTimer, phNewTimer, TimerQueue, Callback, Parameter, DueTime, Period, Flags);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CreateTimerQueueTimer"},
            {"args", {
                {"Callback", Helper::PtrToString(Callback)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    VOID WINAPI Handlers::My_ExitProcess(UINT uExitCode)
    {
        json log = {
            {"dll", "kernel32.dll"}, {"function", "ExitProcess"},
            {"args", {
                {"ExitCode", uExitCode}
            }}
        };
        g_IoctlSender.SendToQueue(log.dump());

        g_ApiHooker.CallOriginal<VOID>((PVOID)My_ExitProcess, uExitCode);
        // 이 함수는 반환하지 않음
    }

    VOID WINAPI Handlers::My_ExitThread(DWORD dwExitCode)
    {
        json log = {
            {"dll", "kernel32.dll"}, {"function", "ExitThread"},
            {"args", {
                {"ExitCode", dwExitCode}
            }}
        };
        g_IoctlSender.SendToQueue(log.dump());

        g_ApiHooker.CallOriginal<VOID>((PVOID)My_ExitThread, dwExitCode);
        // 이 함수는 반환하지 않음
    }

    // 2. Defense Evasion & Code Injection
    LPVOID WINAPI Handlers::My_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
    {
        LPVOID result = g_ApiHooker.CallOriginal<LPVOID>((PVOID)My_VirtualAlloc, lpAddress, dwSize, flAllocationType, flProtect);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "VirtualAlloc"},
            {"args", {
                {"Size", std::to_string(dwSize)},
                {"Protect", Helper::ProtectFlagsToString(flProtect)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    LPVOID WINAPI Handlers::My_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
    {
        LPVOID result = g_ApiHooker.CallOriginal<LPVOID>((PVOID)My_VirtualAllocEx, hProcess, lpAddress, dwSize, flAllocationType, flProtect);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "VirtualAllocEx"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(hProcess)},
                {"Size", std::to_string(dwSize)},
                {"Protect", Helper::ProtectFlagsToString(flProtect)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_VirtualFree, lpAddress, dwSize, dwFreeType);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "VirtualFree"},
            {"args", {
                {"Address", Helper::PtrToString(lpAddress)},
                {"FreeType", Helper::DwordToHexString(dwFreeType)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_VirtualFreeEx, hProcess, lpAddress, dwSize, dwFreeType);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "VirtualFreeEx"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(hProcess)},
                {"Address", Helper::PtrToString(lpAddress)},
                {"FreeType", Helper::DwordToHexString(dwFreeType)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_VirtualProtectEx, hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "VirtualProtectEx"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(hProcess)},
                {"Address", Helper::PtrToString(lpAddress)},
                {"Size", std::to_string(dwSize)},
                {"NewProtect", Helper::ProtectFlagsToString(flNewProtect)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    SIZE_T WINAPI Handlers::My_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
    {
        SIZE_T result = g_ApiHooker.CallOriginal<SIZE_T>((PVOID)My_VirtualQuery, lpAddress, lpBuffer, dwLength);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "VirtualQuery"},
            {"args", {
                {"Address", Helper::PtrToString(lpAddress)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    SIZE_T WINAPI Handlers::My_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
    {
        SIZE_T result = g_ApiHooker.CallOriginal<SIZE_T>((PVOID)My_VirtualQueryEx, hProcess, lpAddress, lpBuffer, dwLength);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "VirtualQueryEx"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(hProcess)},
                {"Address", Helper::PtrToString(lpAddress)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_WriteProcessMemory, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "WriteProcessMemory"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(hProcess)},
                {"BaseAddress", Helper::PtrToString(lpBaseAddress)},
                {"Size", std::to_string(nSize)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    LPVOID WINAPI Handlers::My_MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
    {
        LPVOID result = g_ApiHooker.CallOriginal<LPVOID>((PVOID)My_MapViewOfFile, hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "MapViewOfFile"},
            {"args", {
                {"FileMappingObject", Helper::PtrToString(hFileMappingObject)},
                {"DesiredAccess", Helper::DwordToHexString(dwDesiredAccess)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    LPVOID WINAPI Handlers::My_MapViewOfFileEx(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress)
    {
        LPVOID result = g_ApiHooker.CallOriginal<LPVOID>((PVOID)My_MapViewOfFileEx, hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "MapViewOfFileEx"},
            {"args", {
                {"FileMappingObject", Helper::PtrToString(hFileMappingObject)},
                {"DesiredAccess", Helper::DwordToHexString(dwDesiredAccess)},
                {"BaseAddress", Helper::PtrToString(lpBaseAddress)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_UnmapViewOfFile(LPCVOID lpBaseAddress)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_UnmapViewOfFile, lpBaseAddress);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "UnmapViewOfFile"},
            {"args", {
                {"BaseAddress", Helper::PtrToString(lpBaseAddress)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HMODULE WINAPI Handlers::My_LoadLibraryA(LPCSTR lpLibFileName)
    {
        HMODULE result = g_ApiHooker.CallOriginal<HMODULE>((PVOID)My_LoadLibraryA, lpLibFileName);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "LoadLibraryA"},
            {"args", {
                {"LibFileName", Helper::AstrToString(lpLibFileName)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HMODULE WINAPI Handlers::My_LoadLibraryW(LPCWSTR lpLibFileName)
    {
        HMODULE result = g_ApiHooker.CallOriginal<HMODULE>((PVOID)My_LoadLibraryW, lpLibFileName);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "LoadLibraryW"},
            {"args", {
                {"LibFileName", Helper::WstrToString(lpLibFileName)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HMODULE WINAPI Handlers::My_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
    {
        HMODULE result = g_ApiHooker.CallOriginal<HMODULE>((PVOID)My_LoadLibraryExA, lpLibFileName, hFile, dwFlags);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "LoadLibraryExA"},
            {"args", {
                {"LibFileName", Helper::AstrToString(lpLibFileName)},
                {"Flags", Helper::DwordToHexString(dwFlags)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HMODULE WINAPI Handlers::My_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
    {
        HMODULE result = g_ApiHooker.CallOriginal<HMODULE>((PVOID)My_LoadLibraryExW, lpLibFileName, hFile, dwFlags);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "LoadLibraryExW"},
            {"args", {
                {"LibFileName", Helper::WstrToString(lpLibFileName)},
                {"Flags", Helper::DwordToHexString(dwFlags)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    FARPROC WINAPI Handlers::My_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
    {
        FARPROC result = g_ApiHooker.CallOriginal<FARPROC>((PVOID)My_GetProcAddress, hModule, lpProcName);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "GetProcAddress"},
            {"args", {
                {"Module", Helper::PtrToString(hModule)},
                {"ProcName", (IS_INTRESOURCE(lpProcName) ? "Ordinal:" + std::to_string((UINT_PTR)lpProcName) : Helper::AstrToString(lpProcName))}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_SetThreadContext(HANDLE hThread, const CONTEXT* lpContext)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_SetThreadContext, hThread, lpContext);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "SetThreadContext"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(hThread)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_GetThreadContext, hThread, lpContext);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "GetThreadContext"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(hThread)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_Wow64GetThreadContext(HANDLE hThread, PWOW64_CONTEXT lpContext)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_Wow64GetThreadContext, hThread, lpContext);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "Wow64GetThreadContext"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(hThread)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_Wow64SetThreadContext(HANDLE hThread, const WOW64_CONTEXT* lpContext)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_Wow64SetThreadContext, hThread, lpContext);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "Wow64SetThreadContext"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(hThread)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    DWORD WINAPI Handlers::My_SuspendThread(HANDLE hThread)
    {
        DWORD result = g_ApiHooker.CallOriginal<DWORD>((PVOID)My_SuspendThread, hThread);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "SuspendThread"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(hThread)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    DWORD WINAPI Handlers::My_ResumeThread(HANDLE hThread)
    {
        DWORD result = g_ApiHooker.CallOriginal<DWORD>((PVOID)My_ResumeThread, hThread);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "ResumeThread"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(hThread)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_IsDebuggerPresent()
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_IsDebuggerPresent);

        json log = {
            {"dll", "kernel32.dll"},
            {"function", "IsDebuggerPresent"},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());

        return result;
    }

    BOOL WINAPI Handlers::My_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CheckRemoteDebuggerPresent, hProcess, pbDebuggerPresent);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CheckRemoteDebuggerPresent"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(hProcess)}
            }},
            {"return", result ? "TRUE" : "FALSE"},
            {"result_info", {
                {"IsPresent", (pbDebuggerPresent && *pbDebuggerPresent) ? "TRUE" : "FALSE"}
            }}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    VOID WINAPI Handlers::My_Sleep(DWORD dwMilliseconds)
    {
        json log = {
            {"dll", "kernel32.dll"}, {"function", "Sleep"},
            {"args", {
                {"Milliseconds", std::to_string(dwMilliseconds)}
            }}
        };
        g_IoctlSender.SendToQueue(log.dump());

        g_ApiHooker.CallOriginal<VOID>((PVOID)My_Sleep, dwMilliseconds);
    }

    DWORD WINAPI Handlers::My_SleepEx(DWORD dwMilliseconds, BOOL bAlertable)
    {
        DWORD result = g_ApiHooker.CallOriginal<DWORD>((PVOID)My_SleepEx, dwMilliseconds, bAlertable);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "SleepEx"},
            {"args", {
                {"Milliseconds", std::to_string(dwMilliseconds)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HANDLE WINAPI Handlers::My_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
    {
        HANDLE result = g_ApiHooker.CallOriginal<HANDLE>((PVOID)My_OpenProcess, dwDesiredAccess, bInheritHandle, dwProcessId);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "OpenProcess"},
            {"args", {
                {"ProcessId", std::to_string(dwProcessId)},
                {"DesiredAccess", Helper::DwordToHexString(dwDesiredAccess)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HANDLE WINAPI Handlers::My_OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
    {
        HANDLE result = g_ApiHooker.CallOriginal<HANDLE>((PVOID)My_OpenThread, dwDesiredAccess, bInheritHandle, dwThreadId);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "OpenThread"},
            {"args", {
                {"ThreadId", std::to_string(dwThreadId)},
                {"DesiredAccess", Helper::DwordToHexString(dwDesiredAccess)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HANDLE WINAPI Handlers::My_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
    {
        HANDLE result = g_ApiHooker.CallOriginal<HANDLE>((PVOID)My_CreateToolhelp32Snapshot, dwFlags, th32ProcessID);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CreateToolhelp32Snapshot"},
            {"args", {
                {"Flags", Helper::DwordToHexString(dwFlags)},
                {"ProcessID", std::to_string(th32ProcessID)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    VOID WINAPI Handlers::My_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
    {
        g_ApiHooker.CallOriginal<VOID>((PVOID)My_GetSystemInfo, lpSystemInfo);

        json log = {
            {"dll", "kernel32.dll"},
            {"function", "GetSystemInfo"}
        };
        g_IoctlSender.SendToQueue(log.dump());
    }

    VOID WINAPI Handlers::My_GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo)
    {
        g_ApiHooker.CallOriginal<VOID>((PVOID)My_GetNativeSystemInfo, lpSystemInfo);

        json log = {
            {"dll", "kernel32.dll"},
            {"function", "GetNativeSystemInfo"}
        };
        g_IoctlSender.SendToQueue(log.dump());
    }

    BOOL WINAPI Handlers::My_GetVersionExA(LPOSVERSIONINFOA lpVersionInformation)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_GetVersionExA, lpVersionInformation);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "GetVersionExA"},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_GetVersionExW(LPOSVERSIONINFOW lpVersionInformation)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_GetVersionExW, lpVersionInformation);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "GetVersionExW"},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_GetComputerNameA, lpBuffer, nSize);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "GetComputerNameA"},
            {"return", result ? "TRUE" : "FALSE"},
            {"result_info", {
                {"ComputerName", (result ? Helper::AstrToString(lpBuffer) : "failed")}
            }}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_GetComputerNameW, lpBuffer, nSize);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "GetComputerNameW"},
            {"return", result ? "TRUE" : "FALSE"},
            {"result_info", {
                {"ComputerName", (result ? Helper::WstrToString(lpBuffer) : "failed")}
            }}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_GetComputerNameExA(COMPUTER_NAME_FORMAT NameType, LPSTR lpBuffer, LPDWORD nSize)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_GetComputerNameExA, NameType, lpBuffer, nSize);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "GetComputerNameExA"},
            {"args", {{"NameType", std::to_string(NameType)}}},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_GetComputerNameExW(COMPUTER_NAME_FORMAT NameType, LPWSTR lpBuffer, LPDWORD nSize)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_GetComputerNameExW, NameType, lpBuffer, nSize);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "GetComputerNameExW"},
            {"args", {{"NameType", std::to_string(NameType)}}},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HANDLE WINAPI Handlers::My_GetCurrentProcess()
    {
        // 너무 자주 호출되므로 로깅하지 않음
        return g_ApiHooker.CallOriginal<HANDLE>((PVOID)My_GetCurrentProcess);
    }

    HANDLE WINAPI Handlers::My_GetCurrentThread()
    {
        // 너무 자주 호출되므로 로깅하지 않음
        return g_ApiHooker.CallOriginal<HANDLE>((PVOID)My_GetCurrentThread);
    }

    DWORD WINAPI Handlers::My_GetCurrentProcessId()
    {
        // 너무 자주 호출되므로 로깅하지 않음
        return g_ApiHooker.CallOriginal<DWORD>((PVOID)My_GetCurrentProcessId);
    }

    DWORD WINAPI Handlers::My_GetCurrentThreadId()
    {
        // 너무 자주 호출되므로 로깅하지 않음
        return g_ApiHooker.CallOriginal<DWORD>((PVOID)My_GetCurrentThreadId);
    }

    HANDLE WINAPI Handlers::My_CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
    {
        HANDLE result = g_ApiHooker.CallOriginal<HANDLE>((PVOID)My_CreateNamedPipeA, lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CreateNamedPipeA"},
            {"args", {{"PipeName", Helper::AstrToString(lpName)}}},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HANDLE WINAPI Handlers::My_CreateNamedPipeW(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
    {
        HANDLE result = g_ApiHooker.CallOriginal<HANDLE>((PVOID)My_CreateNamedPipeW, lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CreateNamedPipeW"},
            {"args", {{"PipeName", Helper::WstrToString(lpName)}}},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ConnectNamedPipe, hNamedPipe, lpOverlapped);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "ConnectNamedPipe"},
            {"args", {{"PipeHandle", Helper::PtrToString(hNamedPipe)}}},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_CallNamedPipeA(LPCSTR lpNamedPipeName, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesRead, DWORD nTimeOut)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CallNamedPipeA, lpNamedPipeName, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesRead, nTimeOut);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CallNamedPipeA"},
            {"args", {{"PipeName", Helper::AstrToString(lpNamedPipeName)}}},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_CallNamedPipeW(LPCWSTR lpNamedPipeName, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesRead, DWORD nTimeOut)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CallNamedPipeW, lpNamedPipeName, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesRead, nTimeOut);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CallNamedPipeW"},
            {"args", {{"PipeName", Helper::WstrToString(lpNamedPipeName)}}},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_DuplicateHandle, hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "DuplicateHandle"},
            {"args", {
                {"SourceProcess", Helper::PtrToString(hSourceProcessHandle)},
                {"SourceHandle", Helper::PtrToString(hSourceHandle)},
                {"TargetProcess", Helper::PtrToString(hTargetProcessHandle)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_CloseHandle(HANDLE hObject)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CloseHandle, hObject);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "CloseHandle"},
            {"args", {{"Handle", Helper::PtrToString(hObject)}}},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    DWORD WINAPI Handlers::My_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
    {
        DWORD result = g_ApiHooker.CallOriginal<DWORD>((PVOID)My_WaitForSingleObject, hHandle, dwMilliseconds);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "WaitForSingleObject"},
            {"args", {
                {"Handle", Helper::PtrToString(hHandle)},
                {"Timeout", std::to_string(dwMilliseconds)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    DWORD WINAPI Handlers::My_WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds)
    {
        DWORD result = g_ApiHooker.CallOriginal<DWORD>((PVOID)My_WaitForMultipleObjects, nCount, lpHandles, bWaitAll, dwMilliseconds);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "WaitForMultipleObjects"},
            {"args", {
                {"Count", std::to_string(nCount)},
                {"Timeout", std::to_string(dwMilliseconds)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    DWORD WINAPI Handlers::My_WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable)
    {
        DWORD result = g_ApiHooker.CallOriginal<DWORD>((PVOID)My_WaitForSingleObjectEx, hHandle, dwMilliseconds, bAlertable);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "WaitForSingleObjectEx"},
            {"args", {
                {"Handle", Helper::PtrToString(hHandle)},
                {"Timeout", std::to_string(dwMilliseconds)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    DWORD WINAPI Handlers::My_WaitForMultipleObjectsEx(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds, BOOL bAlertable)
    {
        DWORD result = g_ApiHooker.CallOriginal<DWORD>((PVOID)My_WaitForMultipleObjectsEx, nCount, lpHandles, bWaitAll, dwMilliseconds, bAlertable);

        json log = {
            {"dll", "kernel32.dll"}, {"function", "WaitForMultipleObjectsEx"},
            {"args", {
                {"Count", std::to_string(nCount)},
                {"Timeout", std::to_string(dwMilliseconds)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_TerminateProcess(HANDLE hProcess, UINT uExitCode)
    {
        json log = {
            {"dll", "kernel32.dll"}, {"function", "TerminateProcess"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(hProcess)},
                {"ExitCode", uExitCode}
            }}
        };
        g_IoctlSender.SendToQueue(log.dump());

        return g_ApiHooker.CallOriginal<BOOL>((PVOID)My_TerminateProcess, hProcess, uExitCode);
    }
}

//========================================================================================
//========================================================================================
//
//                                 ADVAPI32.DLL Handlers
//
//========================================================================================
//========================================================================================

extern "C" {

    // 1. Persistence (Services)
    SC_HANDLE WINAPI Handlers::My_CreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword)
    {
        SC_HANDLE result = g_ApiHooker.CallOriginal<SC_HANDLE>((PVOID)My_CreateServiceA, hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "CreateServiceA"},
            {"args", {
                {"ServiceName", Helper::AstrToString(lpServiceName)},
                {"DisplayName", Helper::AstrToString(lpDisplayName)},
                {"BinaryPathName", Helper::AstrToString(lpBinaryPathName)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }


    SC_HANDLE WINAPI Handlers::My_CreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword)
    {
        SC_HANDLE result = g_ApiHooker.CallOriginal<SC_HANDLE>((PVOID)My_CreateServiceW, hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "CreateServiceW"},
            {"args", {
                {"ServiceName", Helper::WstrToString(lpServiceName)},
                {"DisplayName", Helper::WstrToString(lpDisplayName)},
                {"BinaryPathName", Helper::WstrToString(lpBinaryPathName)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_DeleteService(SC_HANDLE hService)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_DeleteService, hService);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "DeleteService"},
            {"args", {
                {"ServiceHandle", Helper::PtrToString(hService)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_ChangeServiceConfigA(SC_HANDLE hService, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword, LPCSTR lpDisplayName)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ChangeServiceConfigA, hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "ChangeServiceConfigA"},
            {"args", {
                {"ServiceHandle", Helper::PtrToString(hService)},
                {"BinaryPathName", Helper::AstrToString(lpBinaryPathName)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_ChangeServiceConfigW(SC_HANDLE hService, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword, LPCWSTR lpDisplayName)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ChangeServiceConfigW, hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "ChangeServiceConfigW"},
            {"args", {
                {"ServiceHandle", Helper::PtrToString(hService)},
                {"BinaryPathName", Helper::WstrToString(lpBinaryPathName)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_ChangeServiceConfig2A(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ChangeServiceConfig2A, hService, dwInfoLevel, lpInfo);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "ChangeServiceConfig2A"},
            {"args", {
                {"ServiceHandle", Helper::PtrToString(hService)},
                {"InfoLevel", std::to_string(dwInfoLevel)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_ChangeServiceConfig2W(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ChangeServiceConfig2W, hService, dwInfoLevel, lpInfo);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "ChangeServiceConfig2W"},
            {"args", {
                {"ServiceHandle", Helper::PtrToString(hService)},
                {"InfoLevel", std::to_string(dwInfoLevel)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_StartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR* lpServiceArgVectors)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_StartServiceA, hService, dwNumServiceArgs, lpServiceArgVectors);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "StartServiceA"},
            {"args", {
                {"ServiceHandle", Helper::PtrToString(hService)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_StartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_StartServiceW, hService, dwNumServiceArgs, lpServiceArgVectors);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "StartServiceW"},
            {"args", {
                {"ServiceHandle", Helper::PtrToString(hService)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_ControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ControlService, hService, dwControl, lpServiceStatus);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "ControlService"},
            {"args", {
                {"ServiceHandle", Helper::PtrToString(hService)},
                {"ControlCode", std::to_string(dwControl)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    // 2. Privilege Escalation & Credential Access
    BOOL WINAPI Handlers::My_OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_OpenProcessToken, ProcessHandle, DesiredAccess, TokenHandle);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "OpenProcessToken"},
            {"args", {
                {"ProcessHandle", Helper::PtrToString(ProcessHandle)},
                {"DesiredAccess", Helper::DwordToHexString(DesiredAccess)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_OpenThreadToken, ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "OpenThreadToken"},
            {"args", {
                {"ThreadHandle", Helper::PtrToString(ThreadHandle)},
                {"DesiredAccess", Helper::DwordToHexString(DesiredAccess)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)
    {
        std::string privName = "N/A";
        if (NewState && NewState->PrivilegeCount > 0) {
            LUID_AND_ATTRIBUTES priv = NewState->Privileges[0];
            char name[256] = { 0 };
            DWORD nameLen = sizeof(name);
            if (LookupPrivilegeNameA(NULL, &priv.Luid, name, &nameLen)) {
                privName = name;
            }
        }

        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_AdjustTokenPrivileges, TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "AdjustTokenPrivileges"},
            {"args", {
                {"TokenHandle", Helper::PtrToString(TokenHandle)},
                {"Privilege", privName}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_DuplicateTokenEx, hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "DuplicateTokenEx"},
            {"args", {
                {"ExistingToken", Helper::PtrToString(hExistingToken)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_ImpersonateLoggedOnUser(HANDLE hToken)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ImpersonateLoggedOnUser, hToken);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "ImpersonateLoggedOnUser"},
            {"args", {
                {"Token", Helper::PtrToString(hToken)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_ImpersonateNamedPipeClient(HANDLE hNamedPipe)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ImpersonateNamedPipeClient, hNamedPipe);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "ImpersonateNamedPipeClient"},
            {"args", {
                {"PipeHandle", Helper::PtrToString(hNamedPipe)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_SetThreadToken(PHANDLE Thread, HANDLE Token)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_SetThreadToken, Thread, Token);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "SetThreadToken"},
            {"args", {
                {"ThreadHandle", (Thread ? Helper::PtrToString(*Thread) : "NULL")},
                {"Token", Helper::PtrToString(Token)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    NTSTATUS NTAPI Handlers::My_LsaOpenPolicy(LSA_HANDLE SystemName, POBJECT_ATTRIBUTES ObjectAttributes, ACCESS_MASK DesiredAccess, PLSA_HANDLE PolicyHandle)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_LsaOpenPolicy, SystemName, ObjectAttributes, DesiredAccess, PolicyHandle);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "LsaOpenPolicy"},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_LsaQueryInformationPolicy(LSA_HANDLE PolicyHandle, POLICY_INFORMATION_CLASS InformationClass, PVOID* Buffer)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_LsaQueryInformationPolicy, PolicyHandle, InformationClass, Buffer);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "LsaQueryInformationPolicy"},
            {"args", {
                {"InfoClass", std::to_string(InformationClass)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_LsaRetrievePrivateData(LSA_HANDLE PolicyHandle, PUNICODE_STRING KeyName, PVOID* PrivateData)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_LsaRetrievePrivateData, PolicyHandle, KeyName, PrivateData);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "LsaRetrievePrivateData"},
            {"args", {
                {"KeyName", (KeyName ? Helper::UnicodeStringToString(*KeyName) : "[null]")}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    // 3. Defense Evasion
    BOOL WINAPI Handlers::My_ClearEventLogA(HANDLE hEventLog, LPCSTR lpBackupFileName)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ClearEventLogA, hEventLog, lpBackupFileName);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "ClearEventLogA"},
            {"args", {
                {"EventLogHandle", Helper::PtrToString(hEventLog)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_ClearEventLogW(HANDLE hEventLog, LPCWSTR lpBackupFileName)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ClearEventLogW, hEventLog, lpBackupFileName);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "ClearEventLogW"},
            {"args", {
                {"EventLogHandle", Helper::PtrToString(hEventLog)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    NTSTATUS NTAPI Handlers::My_LsaSetInformationPolicy(LSA_HANDLE PolicyHandle, POLICY_INFORMATION_CLASS InformationClass, PVOID Buffer)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_LsaSetInformationPolicy, PolicyHandle, InformationClass, Buffer);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "LsaSetInformationPolicy"},
            {"args", {
                {"InfoClass", std::to_string(InformationClass)}
            }},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    NTSTATUS NTAPI Handlers::My_AuditSetSystemPolicy(PVOID pSubCategoryGuids, ULONG dwPolicyCount)
    {
        NTSTATUS status = g_ApiHooker.CallOriginal<NTSTATUS>((PVOID)My_AuditSetSystemPolicy, pSubCategoryGuids, dwPolicyCount);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "AuditSetSystemPolicy"},
            {"return", Helper::DwordToHexString(status)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return status;
    }

    DWORD WINAPI Handlers::My_SetSecurityInfo(HANDLE handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID psidOwner, PSID psidGroup, PACL pDacl, PACL pSacl)
    {
        DWORD result = g_ApiHooker.CallOriginal<DWORD>((PVOID)My_SetSecurityInfo, handle, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "SetSecurityInfo"},
            {"args", {
                {"Handle", Helper::PtrToString(handle)},
                {"ObjectType", std::to_string(ObjectType)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    DWORD WINAPI Handlers::My_SetNamedSecurityInfoA(LPSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID psidOwner, PSID psidGroup, PACL pDacl, PACL pSacl)
    {
        DWORD result = g_ApiHooker.CallOriginal<DWORD>((PVOID)My_SetNamedSecurityInfoA, pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "SetNamedSecurityInfoA"},
            {"args", {
                {"ObjectName", Helper::AstrToString(pObjectName)},
                {"ObjectType", std::to_string(ObjectType)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    DWORD WINAPI Handlers::My_SetNamedSecurityInfoW(LPWSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID psidOwner, PSID psidGroup, PACL pDacl, PACL pSacl)
    {
        DWORD result = g_ApiHooker.CallOriginal<DWORD>((PVOID)My_SetNamedSecurityInfoW, pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "SetNamedSecurityInfoW"},
            {"args", {
                {"ObjectName", Helper::WstrToString(pObjectName)},
                {"ObjectType", std::to_string(ObjectType)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    // 4. Discovery
    BOOL WINAPI Handlers::My_GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_GetUserNameA, lpBuffer, pcbBuffer);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "GetUserNameA"},
            {"return", result ? "TRUE" : "FALSE"},
            {"result_info", {
                {"UserName", (result ? Helper::AstrToString(lpBuffer) : "failed")}
            }}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_GetUserNameW, lpBuffer, pcbBuffer);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "GetUserNameW"},
            {"return", result ? "TRUE" : "FALSE"},
            {"result_info", {
                {"UserName", (result ? Helper::WstrToString(lpBuffer) : "failed")}
            }}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_LookupAccountNameA(LPCSTR lpSystemName, LPCSTR lpAccountName, PSID Sid, LPDWORD cbSid, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_LookupAccountNameA, lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "LookupAccountNameA"},
            {"args", {
                {"AccountName", Helper::AstrToString(lpAccountName)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_LookupAccountNameW(LPCWSTR lpSystemName, LPCWSTR lpAccountName, PSID Sid, LPDWORD cbSid, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_LookupAccountNameW, lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "LookupAccountNameW"},
            {"args", {
                {"AccountName", Helper::WstrToString(lpAccountName)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_LookupAccountSidA(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_LookupAccountSidA, lpSystemName, Sid, Name, cchName, ReferencedDomainName, cchReferencedDomainName, peUse);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "LookupAccountSidA"},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_LookupAccountSidW, lpSystemName, Sid, Name, cchName, ReferencedDomainName, cchReferencedDomainName, peUse);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "LookupAccountSidW"},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_EnumServicesStatusA(SC_HANDLE hSCManager, DWORD dwServiceType, DWORD dwServiceState, LPENUM_SERVICE_STATUSA lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_EnumServicesStatusA, hSCManager, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "EnumServicesStatusA"},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_EnumServicesStatusW(SC_HANDLE hSCManager, DWORD dwServiceType, DWORD dwServiceState, LPENUM_SERVICE_STATUSW lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_EnumServicesStatusW, hSCManager, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "EnumServicesStatusW"},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_EnumServicesStatusExA(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_EnumServicesStatusExA, hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "EnumServicesStatusExA"},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_EnumServicesStatusExW(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCWSTR pszGroupName)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_EnumServicesStatusExW, hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);

        json log = {
            {"dll", "advapi32.dll"}, {"function", "EnumServicesStatusExW"},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

} // extern "C" End for advapi32.dll

// ... (이전에 작성된 ntdll.dll, kernel32.dll, advapi32.dll 핸들러 함수들) ...

//========================================================================================
//========================================================================================
//
//                                  WS2_32.DLL Handlers
//
//========================================================================================
//========================================================================================
/*
extern "C" {

    SOCKET WSAAPI Handlers::My_socket(int af, int type, int protocol)
    {
        using FnType = SOCKET(WSAAPI*)(int, int, int);
        FnType pfnOriginal = (FnType)g_ApiHooker.GetTrampoline((PVOID)My_socket);
        if (!pfnOriginal) { WSASetLastError(WSAEINVAL); return INVALID_SOCKET; }

        SOCKET s = pfnOriginal(af, type, protocol);

        json log = {
            {"dll", "ws2_32.dll"},
            {"function", "socket"},
            {"args", {
                {"af", std::to_string(af)},
                {"type", std::to_string(type)},
                {"protocol", std::to_string(protocol)}
            }},
            {"return", (s == INVALID_SOCKET) ? "INVALID_SOCKET" : std::to_string(s)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return s;
    }

    int WSAAPI Handlers::My_connect(SOCKET s, const struct sockaddr* name, int namelen)
    {
        using FnType = int(WSAAPI*)(SOCKET, const struct sockaddr*, int);
        FnType pfnOriginal = (FnType)g_ApiHooker.GetTrampoline((PVOID)My_connect);
        if (!pfnOriginal) { return SOCKET_ERROR; }

        int result = pfnOriginal(s, name, namelen);

        json log = {
            {"dll", "ws2_32.dll"},
            {"function", "connect"},
            {"args", {
                {"Socket", std::to_string(s)},
                {"RemoteAddress", Helper::SockAddrToString(name)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    int WSAAPI Handlers::My_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS)
    {
        using FnType = int(WSAAPI*)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
        FnType pfnOriginal = (FnType)g_ApiHooker.GetTrampoline((PVOID)My_WSAConnect);
        if (!pfnOriginal) { return SOCKET_ERROR; }

        int result = pfnOriginal(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);

        json log = {
            {"dll", "ws2_32.dll"},
            {"function", "WSAConnect"},
            {"args", {
                {"Socket", std::to_string(s)},
                {"RemoteAddress", Helper::SockAddrToString(name)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    struct hostent* WSAAPI Handlers::My_gethostbyname(const char* name)
    {
        using FnType = struct hostent* (WSAAPI*)(const char*);
        FnType pfnOriginal = (FnType)g_ApiHooker.GetTrampoline((PVOID)My_gethostbyname);
        if (!pfnOriginal) { return NULL; }

        struct hostent* result = pfnOriginal(name);

        json log = {
            {"dll", "ws2_32.dll"},
            {"function", "gethostbyname"},
            {"args", {
                {"HostName", Helper::AstrToString(name)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    int WSAAPI Handlers::My_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult)
    {
        using FnType = int(WSAAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
        FnType pfnOriginal = (FnType)g_ApiHooker.GetTrampoline((PVOID)My_getaddrinfo);
        if (!pfnOriginal) { return WSA_INVALID_PARAMETER; }

        int result = pfnOriginal(pNodeName, pServiceName, pHints, ppResult);

        json log = {
            {"dll", "ws2_32.dll"},
            {"function", "getaddrinfo"},
            {"args", {
                {"NodeName", Helper::AstrToString(pNodeName)},
                {"ServiceName", Helper::AstrToString(pServiceName)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HANDLE WSAAPI Handlers::My_WSAAsyncGetHostByName(HWND hWnd, u_int wMsg, const char* name, char* buf, int buflen)
    {
        using FnType = HANDLE(WSAAPI*)(HWND, u_int, const char*, char*, int);
        FnType pfnOriginal = (FnType)g_ApiHooker.GetTrampoline((PVOID)My_WSAAsyncGetHostByName);
        if (!pfnOriginal) { return 0; }

        HANDLE result = pfnOriginal(hWnd, wMsg, name, buf, buflen);

        json log = {
            {"dll", "ws2_32.dll"},
            {"function", "WSAAsyncGetHostByName"},
            {"args", {
                {"HostName", Helper::AstrToString(name)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    int WSAAPI Handlers::My_closesocket(SOCKET s)
    {
        using FnType = int(WSAAPI*)(SOCKET);
        FnType pfnOriginal = (FnType)g_ApiHooker.GetTrampoline((PVOID)My_closesocket);
        if (!pfnOriginal) { return SOCKET_ERROR; }

        int result = pfnOriginal(s);

        json log = {
            {"dll", "ws2_32.dll"},
            {"function", "closesocket"},
            {"args", {
                {"Socket", std::to_string(s)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    int WSAAPI Handlers::My_ioctlsocket(SOCKET s, long cmd, u_long* argp)
    {
        using FnType = int(WSAAPI*)(SOCKET, long, u_long*);
        FnType pfnOriginal = (FnType)g_ApiHooker.GetTrampoline((PVOID)My_ioctlsocket);
        if (!pfnOriginal) { return SOCKET_ERROR; }

        int result = pfnOriginal(s, cmd, argp);

        json log = {
            {"dll", "ws2_32.dll"},
            {"function", "ioctlsocket"},
            {"args", {
                {"Socket", std::to_string(s)},
                {"Command", Helper::DwordToHexString(cmd)}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }
} // extern "C" End
*/
//========================================================================================
//========================================================================================
//
//                                  USER32.DLL Handlers
//
//========================================================================================
//========================================================================================

extern "C" {

    HHOOK WINAPI Handlers::My_SetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)
    {
        HHOOK result = g_ApiHooker.CallOriginal<HHOOK>((PVOID)My_SetWindowsHookExA, idHook, lpfn, hmod, dwThreadId);

        json log = {
            {"dll", "user32.dll"}, {"function", "SetWindowsHookExA"},
            {"args", {
                {"HookType", std::to_string(idHook)},
                {"ThreadId", std::to_string(dwThreadId)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HHOOK WINAPI Handlers::My_SetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)
    {
        HHOOK result = g_ApiHooker.CallOriginal<HHOOK>((PVOID)My_SetWindowsHookExW, idHook, lpfn, hmod, dwThreadId);

        json log = {
            {"dll", "user32.dll"}, {"function", "SetWindowsHookExW"},
            {"args", {
                {"HookType", std::to_string(idHook)},
                {"ThreadId", std::to_string(dwThreadId)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_UnhookWindowsHookEx(HHOOK hhk)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_UnhookWindowsHookEx, hhk);

        json log = {
            {"dll", "user32.dll"}, {"function", "UnhookWindowsHookEx"},
            {"args", {
                {"HookHandle", Helper::PtrToString(hhk)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    SHORT WINAPI Handlers::My_GetAsyncKeyState(int vKey)
    {
        // 이 함수는 매우 자주 호출되므로, 로깅 없이 원본 함수만 호출합니다.
        return g_ApiHooker.CallOriginal<SHORT>((PVOID)My_GetAsyncKeyState, vKey);
    }

    SHORT WINAPI Handlers::My_GetKeyState(int nVirtKey)
    {
        // 이 함수는 매우 자주 호출되므로, 로깅 없이 원본 함수만 호출합니다.
        return g_ApiHooker.CallOriginal<SHORT>((PVOID)My_GetKeyState, nVirtKey);
    }

    BOOL WINAPI Handlers::My_GetKeyboardState(PBYTE lpKeyState)
    {
        // 이 함수는 매우 자주 호출되므로, 로깅 없이 원본 함수만 호출합니다.
        return g_ApiHooker.CallOriginal<BOOL>((PVOID)My_GetKeyboardState, lpKeyState);
    }

    BOOL WINAPI Handlers::My_ShowWindow(HWND hWnd, int nCmdShow)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ShowWindow, hWnd, nCmdShow);

        json log = {
            {"dll", "user32.dll"}, {"function", "ShowWindow"},
            {"args", {
                {"hWnd", Helper::PtrToString(hWnd)},
                {"Command", (nCmdShow == SW_HIDE ? "SW_HIDE" : std::to_string(nCmdShow))}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HWND WINAPI Handlers::My_FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName)
    {
        HWND result = g_ApiHooker.CallOriginal<HWND>((PVOID)My_FindWindowA, lpClassName, lpWindowName);

        json log = {
            {"dll", "user32.dll"}, {"function", "FindWindowA"},
            {"args", {
                {"ClassName", Helper::AstrToString(lpClassName)},
                {"WindowName", Helper::AstrToString(lpWindowName)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HWND WINAPI Handlers::My_FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName)
    {
        HWND result = g_ApiHooker.CallOriginal<HWND>((PVOID)My_FindWindowW, lpClassName, lpWindowName);

        json log = {
            {"dll", "user32.dll"}, {"function", "FindWindowW"},
            {"args", {
                {"ClassName", Helper::WstrToString(lpClassName)},
                {"WindowName", Helper::WstrToString(lpWindowName)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HWND WINAPI Handlers::My_GetForegroundWindow()
    {
        // 이 함수는 매우 자주 호출될 수 있으므로, 로깅 없이 원본 함수만 호출합니다.
        return g_ApiHooker.CallOriginal<HWND>((PVOID)My_GetForegroundWindow);
    }

    HWND WINAPI Handlers::My_CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
    {
        HWND result = g_ApiHooker.CallOriginal<HWND>((PVOID)My_CreateWindowExA, dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);

        json log = {
            {"dll", "user32.dll"}, {"function", "CreateWindowExA"},
            {"args", {
                {"ClassName", Helper::AstrToString(lpClassName)},
                {"WindowName", Helper::AstrToString(lpWindowName)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HWND WINAPI Handlers::My_CreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
    {
        HWND result = g_ApiHooker.CallOriginal<HWND>((PVOID)My_CreateWindowExW, dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);

        json log = {
            {"dll", "user32.dll"}, {"function", "CreateWindowExW"},
            {"args", {
                {"ClassName", Helper::WstrToString(lpClassName)},
                {"WindowName", Helper::WstrToString(lpWindowName)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

} // extern "C" End for user32.dll


//========================================================================================
//========================================================================================
//
//                                  GDI32.DLL Handlers
//
//========================================================================================
//========================================================================================

extern "C" {

    HDC WINAPI Handlers::My_CreateDCA(LPCSTR pwszDriver, LPCSTR pwszDevice, LPCSTR pszPort, const DEVMODEA* pdm)
    {
        HDC result = g_ApiHooker.CallOriginal<HDC>((PVOID)My_CreateDCA, pwszDriver, pwszDevice, pszPort, pdm);

        json log = {
            {"dll", "gdi32.dll"}, {"function", "CreateDCA"},
            {"args", {{"Device", Helper::AstrToString(pwszDevice)}}},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HDC WINAPI Handlers::My_CreateDCW(LPCWSTR pwszDriver, LPCWSTR pwszDevice, LPCWSTR pszPort, const DEVMODEW* pdm)
    {
        HDC result = g_ApiHooker.CallOriginal<HDC>((PVOID)My_CreateDCW, pwszDriver, pwszDevice, pszPort, pdm);

        json log = {
            {"dll", "gdi32.dll"}, {"function", "CreateDCW"},
            {"args", {{"Device", Helper::WstrToString(pwszDevice)}}},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HDC WINAPI Handlers::My_CreateCompatibleDC(HDC hdc)
    {
        HDC result = g_ApiHooker.CallOriginal<HDC>((PVOID)My_CreateCompatibleDC, hdc);

        json log = {
            {"dll", "gdi32.dll"}, {"function", "CreateCompatibleDC"},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HDC WINAPI Handlers::My_GetDC(HWND hWnd)
    {
        HDC result = g_ApiHooker.CallOriginal<HDC>((PVOID)My_GetDC, hWnd);

        json log = {
            {"dll", "gdi32.dll"}, {"function", "GetDC"},
            {"args", {{"hWnd", Helper::PtrToString(hWnd)}}},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HBITMAP WINAPI Handlers::My_CreateCompatibleBitmap(HDC hdc, int cx, int cy)
    {
        HBITMAP result = g_ApiHooker.CallOriginal<HBITMAP>((PVOID)My_CreateCompatibleBitmap, hdc, cx, cy);

        json log = {
            {"dll", "gdi32.dll"}, {"function", "CreateCompatibleBitmap"},
            {"args", {
                {"Width", std::to_string(cx)},
                {"Height", std::to_string(cy)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_BitBlt(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_BitBlt, hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);

        if (rop == SRCCOPY) { // 화면 캡처와 같은 작업만 로깅 (노이즈 감소)
            json log = {
                {"dll", "gdi32.dll"}, {"function", "BitBlt"},
                {"args", {
                    {"ROP", Helper::DwordToHexString(rop)}
                }},
                {"return", result ? "TRUE" : "FALSE"}
            };
            g_IoctlSender.SendToQueue(log.dump());
        }
        return result;
    }


    // ... (이하 모든 gdi32, wininet 등 나머지 핸들러 구현)
}

//========================================================================================
//========================================================================================
//
//                                 WININET.DLL Handlers
//
//========================================================================================
//========================================================================================

extern "C" {

    HINTERNET WINAPI Handlers::My_InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
    {
        HINTERNET result = g_ApiHooker.CallOriginal<HINTERNET>((PVOID)My_InternetOpenA, lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);

        json log = {
            {"dll", "wininet.dll"}, {"function", "InternetOpenA"},
            {"args", {
                {"UserAgent", Helper::AstrToString(lpszAgent)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HINTERNET WINAPI Handlers::My_InternetOpenW(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags)
    {
        HINTERNET result = g_ApiHooker.CallOriginal<HINTERNET>((PVOID)My_InternetOpenW, lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);

        json log = {
            {"dll", "wininet.dll"}, {"function", "InternetOpenW"},
            {"args", {
                {"UserAgent", Helper::WstrToString(lpszAgent)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }


    HINTERNET WINAPI Handlers::My_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
    {
        HINTERNET result = g_ApiHooker.CallOriginal<HINTERNET>((PVOID)My_InternetConnectA, hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);

        json log = {
            {"dll", "wininet.dll"}, {"function", "InternetConnectA"},
            {"args", {
                {"ServerName", Helper::AstrToString(lpszServerName)},
                {"Port", std::to_string(nServerPort)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HINTERNET WINAPI Handlers::My_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
    {
        HINTERNET result = g_ApiHooker.CallOriginal<HINTERNET>((PVOID)My_InternetConnectW, hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);

        json log = {
            {"dll", "wininet.dll"}, {"function", "InternetConnectW"},
            {"args", {
                {"ServerName", Helper::WstrToString(lpszServerName)},
                {"Port", std::to_string(nServerPort)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HINTERNET WINAPI Handlers::My_HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
    {
        HINTERNET result = g_ApiHooker.CallOriginal<HINTERNET>((PVOID)My_HttpOpenRequestA, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);

        json log = {
            {"dll", "wininet.dll"}, {"function", "HttpOpenRequestA"},
            {"args", {
                {"Verb", Helper::AstrToString(lpszVerb)},
                {"ObjectName", Helper::AstrToString(lpszObjectName)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HINTERNET WINAPI Handlers::My_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
    {
        HINTERNET result = g_ApiHooker.CallOriginal<HINTERNET>((PVOID)My_HttpOpenRequestW, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);

        json log = {
            {"dll", "wininet.dll"}, {"function", "HttpOpenRequestW"},
            {"args", {
                {"Verb", Helper::WstrToString(lpszVerb)},
                {"ObjectName", Helper::WstrToString(lpszObjectName)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_HttpSendRequestA, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);

        json log = {
            {"dll", "wininet.dll"}, {"function", "HttpSendRequestA"},
            {"args", {
                {"RequestHandle", Helper::PtrToString(hRequest)},
                {"Headers", Helper::AstrToString(lpszHeaders)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_HttpSendRequestW, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);

        json log = {
            {"dll", "wininet.dll"}, {"function", "HttpSendRequestW"},
            {"args", {
                {"RequestHandle", Helper::PtrToString(hRequest)},
                {"Headers", Helper::WstrToString(lpszHeaders)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_InternetReadFile, hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);

        json log = {
            {"dll", "wininet.dll"}, {"function", "InternetReadFile"},
            {"args", {
                {"Handle", Helper::PtrToString(hFile)},
                {"BytesRead_Out", (result && lpdwNumberOfBytesRead) ? std::to_string(*lpdwNumberOfBytesRead) : "0"}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_InternetWriteFile(HINTERNET hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_InternetWriteFile, hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);

        json log = {
            {"dll", "wininet.dll"}, {"function", "InternetWriteFile"},
            {"args", {
                {"Handle", Helper::PtrToString(hFile)},
                {"BytesToWrite", std::to_string(dwNumberOfBytesToWrite)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

} // extern "C" End for wininet.dll

//========================================================================================
//========================================================================================
//
//                                  SHELL32.DLL Handlers
//
//========================================================================================
//========================================================================================

extern "C" {

    HINSTANCE WINAPI Handlers::My_ShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd)
    {
        HINSTANCE result = g_ApiHooker.CallOriginal<HINSTANCE>((PVOID)My_ShellExecuteA, hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);

        json log = {
            {"dll", "shell32.dll"}, {"function", "ShellExecuteA"},
            {"args", {
                {"Operation", Helper::AstrToString(lpOperation)},
                {"File", Helper::AstrToString(lpFile)},
                {"Parameters", Helper::AstrToString(lpParameters)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HINSTANCE WINAPI Handlers::My_ShellExecuteW(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd)
    {
        HINSTANCE result = g_ApiHooker.CallOriginal<HINSTANCE>((PVOID)My_ShellExecuteW, hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);

        json log = {
            {"dll", "shell32.dll"}, {"function", "ShellExecuteW"},
            {"args", {
                {"Operation", Helper::WstrToString(lpOperation)},
                {"File", Helper::WstrToString(lpFile)},
                {"Parameters", Helper::WstrToString(lpParameters)}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_ShellExecuteExA(SHELLEXECUTEINFOA* pExecInfo)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ShellExecuteExA, pExecInfo);

        json log = {
            {"dll", "shell32.dll"}, {"function", "ShellExecuteExA"},
            {"args", {
                {"File", (pExecInfo ? Helper::AstrToString(pExecInfo->lpFile) : "[null]")},
                {"Parameters", (pExecInfo ? Helper::AstrToString(pExecInfo->lpParameters) : "[null]")}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_ShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_ShellExecuteExW, pExecInfo);

        json log = {
            {"dll", "shell32.dll"}, {"function", "ShellExecuteExW"},
            {"args", {
                {"File", (pExecInfo ? Helper::WstrToString(pExecInfo->lpFile) : "[null]")},
                {"Parameters", (pExecInfo ? Helper::WstrToString(pExecInfo->lpParameters) : "[null]")}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HRESULT STDAPICALLTYPE Handlers::My_SHGetSpecialFolderPathA(HWND hwnd, LPSTR pszPath, int csidl, BOOL fCreate)
    {
        HRESULT result = g_ApiHooker.CallOriginal<HRESULT>((PVOID)My_SHGetSpecialFolderPathA, hwnd, pszPath, csidl, fCreate);

        json log = {
            {"dll", "shell32.dll"}, {"function", "SHGetSpecialFolderPathA"},
            {"args", {
                {"CSIDL", std::to_string(csidl)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HRESULT STDAPICALLTYPE Handlers::My_SHGetSpecialFolderPathW(HWND hwnd, LPWSTR pszPath, int csidl, BOOL fCreate)
    {
        HRESULT result = g_ApiHooker.CallOriginal<HRESULT>((PVOID)My_SHGetSpecialFolderPathW, hwnd, pszPath, csidl, fCreate);

        json log = {
            {"dll", "shell32.dll"}, {"function", "SHGetSpecialFolderPathW"},
            {"args", {
                {"CSIDL", std::to_string(csidl)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HRESULT STDAPICALLTYPE Handlers::My_SHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPSTR pszPath)
    {
        HRESULT result = g_ApiHooker.CallOriginal<HRESULT>((PVOID)My_SHGetFolderPathA, hwnd, csidl, hToken, dwFlags, pszPath);

        json log = {
            {"dll", "shell32.dll"}, 
            {"function", "SHGetFolderPathA"},
            {"args", {
                {"CSIDL", std::to_string(csidl)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HRESULT STDAPICALLTYPE Handlers::My_SHGetFolderPathW(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPWSTR pszPath)
    {
        HRESULT result = g_ApiHooker.CallOriginal<HRESULT>((PVOID)My_SHGetFolderPathW, hwnd, csidl, hToken, dwFlags, pszPath);

        json log = {
            {"dll", "shell32.dll"}, {"function", "SHGetFolderPathW"},
            {"args", {
                {"CSIDL", std::to_string(csidl)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

} // extern "C" End for shell32.dll

//========================================================================================
//========================================================================================
//
//                                 CRYPT32.DLL Handlers
//
//========================================================================================
//========================================================================================

extern "C" {

    BOOL WINAPI Handlers::My_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CryptEncrypt, hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);

        json log = {
            {"dll", "crypt32.dll"}, {"function", "CryptEncrypt"},
            {"args", {
                {"KeyHandle", Helper::PtrToString((PVOID)hKey)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CryptDecrypt, hKey, hHash, Final, dwFlags, pbData, pdwDataLen);

        json log = {
            {"dll", "crypt32.dll"}, {"function", "CryptDecrypt"},
            {"args", {
                {"KeyHandle", Helper::PtrToString((PVOID)hKey)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CryptGenKey, hProv, Algid, dwFlags, phKey);

        json log = {
            {"dll", "crypt32.dll"}, {"function", "CryptGenKey"},
            {"args", {
                {"Algorithm", Helper::DwordToHexString(Algid)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_CryptImportKey(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CryptImportKey, hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);

        json log = {
            {"dll", "crypt32.dll"}, {"function", "CryptImportKey"},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HCERTSTORE WINAPI Handlers::My_CertOpenStore(LPCSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV_LEGACY hCryptProv, DWORD dwFlags, const void* pvPara)
    {
        HCERTSTORE result = g_ApiHooker.CallOriginal<HCERTSTORE>((PVOID)My_CertOpenStore, lpszStoreProvider, dwEncodingType, hCryptProv, dwFlags, pvPara);

        json log = {
            {"dll", "crypt32.dll"}, {"function", "CertOpenStore"},
            {"args", {
                {"StoreProvider", Helper::AstrToString(lpszStoreProvider)},
                {"Para", (pvPara ? Helper::AstrToString((LPCSTR)pvPara) : "[null]")}
            }},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    BOOL WINAPI Handlers::My_CertAddCertificateContextToStore(HCERTSTORE hCertStore, PCCERT_CONTEXT pCertContext, DWORD dwAddDisposition, PCCERT_CONTEXT* ppStoreContext)
    {
        BOOL result = g_ApiHooker.CallOriginal<BOOL>((PVOID)My_CertAddCertificateContextToStore, hCertStore, pCertContext, dwAddDisposition, ppStoreContext);

        json log = {
            {"dll", "crypt32.dll"}, {"function", "CertAddCertificateContextToStore"},
            {"args", {
                {"StoreHandle", Helper::PtrToString(hCertStore)}
            }},
            {"return", result ? "TRUE" : "FALSE"}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HCERTSTORE WINAPI Handlers::My_PFXImportCertStore(CRYPT_DATA_BLOB* pPFX, LPCWSTR szPassword, DWORD dwFlags)
    {
        HCERTSTORE result = g_ApiHooker.CallOriginal<HCERTSTORE>((PVOID)My_PFXImportCertStore, pPFX, szPassword, dwFlags);

        json log = {
            {"dll", "crypt32.dll"}, {"function", "PFXImportCertStore"},
            {"return", Helper::PtrToString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

} // extern "C" End for crypt32.dll

//========================================================================================
//========================================================================================
//
//                          OLE32.DLL / COMBASE.DLL Handlers
//
//========================================================================================
//========================================================================================

extern "C" {

    HRESULT STDAPICALLTYPE Handlers::My_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv)
    {
        HRESULT result = g_ApiHooker.CallOriginal<HRESULT>((PVOID)My_CoCreateInstance, rclsid, pUnkOuter, dwClsContext, riid, ppv);

        json log = {
            {"dll", "ole32.dll"}, {"function", "CoCreateInstance"},
            {"args", {
                {"CLSID", Helper::GuidToString(rclsid)},
                {"IID", Helper::GuidToString(riid)},
                {"ClsContext", Helper::DwordToHexString(dwClsContext)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HRESULT STDAPICALLTYPE Handlers::My_CoCreateInstance_combase(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv)
    {
        HRESULT result = g_ApiHooker.CallOriginal<HRESULT>((PVOID)My_CoCreateInstance_combase, rclsid, pUnkOuter, dwClsContext, riid, ppv);

        json log = {
            {"dll", "combase.dll"}, {"function", "CoCreateInstance"},
            {"args", {
                {"CLSID", Helper::GuidToString(rclsid)},
                {"IID", Helper::GuidToString(riid)},
                {"ClsContext", Helper::DwordToHexString(dwClsContext)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HRESULT STDAPICALLTYPE Handlers::My_CoCreateInstanceEx(REFCLSID rclsid, IUnknown* punkOuter, DWORD dwClsCtx, COSERVERINFO* pServerInfo, DWORD dwCount, MULTI_QI* pResults)
    {
        HRESULT result = g_ApiHooker.CallOriginal<HRESULT>((PVOID)My_CoCreateInstanceEx, rclsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults);

        json log = {

            {"dll", "ole32.dll"}, {"function", "CoCreateInstanceEx"},
            {"args", {
                {"CLSID", Helper::GuidToString(rclsid)},
                {"ClsContext", Helper::DwordToHexString(dwClsCtx)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HRESULT STDAPICALLTYPE Handlers::My_CoCreateInstanceEx_combase(REFCLSID rclsid, IUnknown* punkOuter, DWORD dwClsCtx, COSERVERINFO* pServerInfo, DWORD dwCount, MULTI_QI* pResults)
    {
        HRESULT result = g_ApiHooker.CallOriginal<HRESULT>((PVOID)My_CoCreateInstanceEx_combase, rclsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults);

        json log = {
            {"dll", "combase.dll"}, {"function", "CoCreateInstanceEx"},
            {"args", {
                {"CLSID", Helper::GuidToString(rclsid)},
                {"ClsContext", Helper::DwordToHexString(dwClsCtx)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

    HRESULT STDAPICALLTYPE Handlers::My_CoGetObject(LPCWSTR pszName, BIND_OPTS* pBindOptions, REFIID riid, void** ppv)
    {
        HRESULT result = g_ApiHooker.CallOriginal<HRESULT>((PVOID)My_CoGetObject, pszName, pBindOptions, riid, ppv);

        json log = {
            {"dll", "ole32.dll"}, {"function", "CoGetObject"},
            {"args", {
                {"MonikerName", Helper::WstrToString(pszName)},
                {"IID", Helper::GuidToString(riid)}
            }},
            {"return", Helper::DwordToHexString(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

} // extern "C" End for ole32/combase.dll

//========================================================================================
//========================================================================================
//
//                                 WINTRUST.DLL Handlers
//
//========================================================================================
//========================================================================================

extern "C" {

    LONG WINAPI Handlers::My_WinVerifyTrust(HWND hwnd, GUID* pgActionID, LPVOID pWVTData)
    {
        LONG result = g_ApiHooker.CallOriginal<LONG>((PVOID)My_WinVerifyTrust, hwnd, pgActionID, pWVTData);

        json log = {
            {"dll", "wintrust.dll"}, {"function", "WinVerifyTrust"},
            {"args", {
                {"ActionID", (pgActionID ? Helper::GuidToString(*pgActionID) : "[null]")}
            }},
            {"return", std::to_string(result)}
        };
        g_IoctlSender.SendToQueue(log.dump());
        return result;
    }

} // extern "C" End for wintrust.dll


namespace EDR
{
    namespace Util
    {
        namespace API_Hook
        {
            namespace Handlers
            {
                std::vector<RAW_API_HOOK> g_API_Hooks = {

                    // ========================================================================
    // 그룹 1: 실행 (Execution) & 지속성 (Persistence)
    // - MITRE T1059, T1569, T1053, T1547, T1543
    // - 새로운 프로세스 생성, 서비스/드라이버 등록 등 공격의 시작점과 생존 전략을 탐지합니다.
    // ========================================================================
    {"advapi32.dll", "CreateServiceW", (PVOID)My_CreateServiceW},
    {"advapi32.dll", "StartServiceW", (PVOID)My_StartServiceW},
    {"ntdll.dll", "NtLoadDriver", (PVOID)My_NtLoadDriver},
    {"ole32.dll", "CoCreateInstance", (PVOID)My_CoCreateInstance}, // WMI, Task Scheduler 등 COM 기반 실행/지속성

    // ========================================================================
    // 그룹 2: 코드 인젝션 & 방어 회피 (Process Injection & Defense Evasion)
    // - MITRE T1055, T1027, T1134, T1070
    // - 파일리스 공격, 프로세스 하이재킹, 안티 디버깅 등 가장 정교한 위협 행위를 탐지합니다.
    // ========================================================================
    {"kernel32.dll", "CreateRemoteThread", (PVOID)My_CreateRemoteThread}, // 원격 스레드 실행
    {"ntdll.dll", "NtQueueApcThread", (PVOID)My_NtQueueApcThread}, // APC Injection
    {"ntdll.dll", "NtSetContextThread", (PVOID)My_NtSetContextThread}, // Process Hollowing, Thread Hijacking
    {"ntdll.dll", "NtMapViewOfSection", (PVOID)My_NtMapViewOfSection}, // Process Hollowing, Reflective Loading
    {"ntdll.dll", "NtSetInformationThread", (PVOID)My_NtSetInformationThread}, // 특히 ThreadHideFromDebugger
    {"advapi32.dll", "ClearEventLogW", (PVOID)My_ClearEventLogW}, // 로그 삭제 (흔적 제거)

    // ========================================================================
    // 그룹 3: 권한 상승 & 자격 증명 접근 (Privilege Escalation & Credential Access)
    // - MITRE T1068, T1134, T1003
    // - 시스템 권한을 획득하고 다른 계정 정보를 탈취하려는 시도를 탐지합니다.
    // ========================================================================
    {"kernel32.dll", "OpenProcess", (PVOID)My_OpenProcess}, // lsass.exe 등 민감한 프로세스 접근 시도
    {"advapi32.dll", "OpenProcessToken", (PVOID)My_OpenProcessToken},
    {"advapi32.dll", "AdjustTokenPrivileges", (PVOID)My_AdjustTokenPrivileges}, // SeDebugPrivilege 등 획득 시도
    {"advapi32.dll", "ImpersonateLoggedOnUser", (PVOID)My_ImpersonateLoggedOnUser},
    {"advapi32.dll", "LsaRetrievePrivateData", (PVOID)My_LsaRetrievePrivateData}, // LSA Secrets 탈취

    // ========================================================================
    // 그룹 4: 정보 수집 & C2 통신 (Discovery, Collection & C2)
    // - MITRE T1057, T1087, T1113, T1071
    // - 시스템 정보를 수집하고, 화면을 캡처하며, 외부 서버와 통신하는 행위를 탐지합니다.
    // ========================================================================
    {"kernel32.dll", "CreateToolhelp32Snapshot", (PVOID)My_CreateToolhelp32Snapshot}, // 프로세스 목록 확인
    {"advapi32.dll", "GetUserNameW", (PVOID)My_GetUserNameW},
    {"user32.dll", "SetWindowsHookExW", (PVOID)My_SetWindowsHookExW}, // 키로깅 시도
    {"gdi32.dll", "BitBlt", (PVOID)My_BitBlt}, // 화면 캡처
    {"wininet.dll", "InternetConnectW", (PVOID)My_InternetConnectW}, // C2 서버 주소 확인
    {"wininet.dll", "HttpSendRequestW", (PVOID)My_HttpSendRequestW}, // 데이터 유출/명령 수신
    // {"ws2_32.dll", "connect", (PVOID)My_connect}, // WinINet을 안 쓰는 C2 통신용. 필요 시 활성화.

    // ========================================================================
    // 그룹 5: 영향 (Impact)
    // - MITRE T1486, T1489
    // - 랜섬웨어의 파일 암호화, 주요 서비스 중단 등의 파괴 행위를 탐지합니다.
    // ========================================================================
    {"crypt32.dll", "CryptEncrypt", (PVOID)My_CryptEncrypt}, // 파일 암호화 행위
    {"kernel32.dll", "TerminateProcess", (PVOID)My_TerminateProcess}, // 보안 프로세스 종료 시도
    {"advapi32.dll", "ControlService", (PVOID)My_ControlService} // 서비스 중지/삭제
                    //{"kernel32.dll", "VirtualAlloc", (PVOID)My_VirtualAlloc},

                    /*
                    // 1. Thread Manipulation
                    {"ntdll.dll", "NtSuspendThread", (PVOID)My_NtSuspendThread},
                    {"ntdll.dll", "NtResumeThread", (PVOID)My_NtResumeThread},

                    // 2. Code Injection & Memory Manipulation
                    {"ntdll.dll", "NtCreateSection", (PVOID)My_NtCreateSection},
                    {"ntdll.dll", "NtMapViewOfSection", (PVOID)My_NtMapViewOfSection},
                    {"ntdll.dll", "NtUnmapViewOfSection", (PVOID)My_NtUnmapViewOfSection},
                    {"ntdll.dll", "NtQueueApcThread", (PVOID)My_NtQueueApcThread},
                    {"ntdll.dll", "NtGetContextThread", (PVOID)My_NtGetContextThread},
                    {"ntdll.dll", "NtSetContextThread", (PVOID)My_NtSetContextThread},

                    // 3. Privilege Escalation & Token Manipulation
                    {"ntdll.dll", "NtOpenProcessToken", (PVOID)My_NtOpenProcessToken},
                    {"ntdll.dll", "NtOpenThreadToken", (PVOID)My_NtOpenThreadToken},
                    {"ntdll.dll", "NtAdjustPrivilegesToken", (PVOID)My_NtAdjustPrivilegesToken},
                    {"ntdll.dll", "NtDuplicateToken", (PVOID)My_NtDuplicateToken},
                    {"ntdll.dll", "NtFilterToken", (PVOID)My_NtFilterToken},
                    {"ntdll.dll", "NtImpersonateThread", (PVOID)My_NtImpersonateThread},
                    {"ntdll.dll", "NtImpersonateClientOfPort", (PVOID)My_NtImpersonateClientOfPort},

                    // 4. Persistence (Non-File)
                    {"ntdll.dll", "NtLoadDriver", (PVOID)My_NtLoadDriver},
                    {"ntdll.dll", "NtUnloadDriver", (PVOID)My_NtUnloadDriver},
                    {"ntdll.dll", "NtCreateWnfStateName", (PVOID)My_NtCreateWnfStateName},
                    {"ntdll.dll", "NtUpdateWnfStateData", (PVOID)My_NtUpdateWnfStateData},

                    // 5. Defense Evasion & Stealth
                    {"ntdll.dll", "NtSetInformationThread", (PVOID)My_NtSetInformationThread},
                    {"ntdll.dll", "NtSetInformationProcess", (PVOID)My_NtSetInformationProcess},
                    {"ntdll.dll", "NtRemoveProcessDebug", (PVOID)My_NtRemoveProcessDebug},
                    {"ntdll.dll", "NtSetInformationDebugObject", (PVOID)My_NtSetInformationDebugObject},
                    {"ntdll.dll", "NtSystemDebugControl", (PVOID)My_NtSystemDebugControl},
                    //{"ntdll.dll", "NtClose", (PVOID)My_NtClose},
                    {"ntdll.dll", "NtDelayExecution", (PVOID)My_NtDelayExecution},

                    // 6. Discovery & Reconnaissance (Non-File)
                    {"ntdll.dll", "NtQuerySystemInformation", (PVOID)My_NtQuerySystemInformation},
                    {"ntdll.dll", "NtQueryInformationProcess", (PVOID)My_NtQueryInformationProcess},
                    {"ntdll.dll", "NtQueryVirtualMemory", (PVOID)My_NtQueryVirtualMemory},
                    {"ntdll.dll", "NtQueryObject", (PVOID)My_NtQueryObject},
                    {"ntdll.dll", "NtQuerySystemEnvironmentValue", (PVOID)My_NtQuerySystemEnvironmentValue},
                    {"ntdll.dll", "NtQuerySystemEnvironmentValueEx", (PVOID)My_NtQuerySystemEnvironmentValueEx},

                    // 7. Module Loading & Dynamic API Resolving
                    {"ntdll.dll", "LdrLoadDll", (PVOID)My_LdrLoadDll},
                    {"ntdll.dll", "LdrGetProcedureAddress", (PVOID)My_LdrGetProcedureAddress},

                    // kernel32.dll Functions
                    //=====================================================
                    // kernel32.dll - Final EDR Hooks (Non-File, Non-Registry)
                    //=====================================================

                    // 1. Execution
                    {"kernel32.dll", "CreateProcessA", (PVOID)My_CreateProcessA},
                    {"kernel32.dll", "CreateProcessW", (PVOID)My_CreateProcessW},
                    {"kernel32.dll", "CreateProcessAsUserA", (PVOID)My_CreateProcessAsUserA},
                    {"kernel32.dll", "CreateProcessAsUserW", (PVOID)My_CreateProcessAsUserW},
                    {"kernel32.dll", "CreateRemoteThread", (PVOID)My_CreateRemoteThread},
                    {"kernel32.dll", "CreateRemoteThreadEx", (PVOID)My_CreateRemoteThreadEx},
                    {"kernel32.dll", "WinExec", (PVOID)My_WinExec},
                    {"kernel32.dll", "QueueUserWorkItem", (PVOID)My_QueueUserWorkItem},
                    {"kernel32.dll", "CreateTimerQueueTimer", (PVOID)My_CreateTimerQueueTimer},
                    {"kernel32.dll", "ExitProcess", (PVOID)My_ExitProcess},
                    {"kernel32.dll", "ExitThread", (PVOID)My_ExitThread},

                    // 2. Defense Evasion & Code Injection
                    //{"kernel32.dll", "VirtualAlloc", (PVOID)My_VirtualAlloc},
                    {"kernel32.dll", "VirtualAllocEx", (PVOID)My_VirtualAllocEx},
                    //{"kernel32.dll", "VirtualFree", (PVOID)My_VirtualFree},
                    {"kernel32.dll", "VirtualFreeEx", (PVOID)My_VirtualFreeEx},
                    //{"kernel32.dll", "VirtualProtectEx", (PVOID)My_VirtualProtectEx},
                    {"kernel32.dll", "VirtualQuery", (PVOID)My_VirtualQuery},
                    {"kernel32.dll", "VirtualQueryEx", (PVOID)My_VirtualQueryEx},
                    {"kernel32.dll", "WriteProcessMemory", (PVOID)My_WriteProcessMemory},
                    {"kernel32.dll", "MapViewOfFile", (PVOID)My_MapViewOfFile},
                    {"kernel32.dll", "MapViewOfFileEx", (PVOID)My_MapViewOfFileEx},
                    {"kernel32.dll", "UnmapViewOfFile", (PVOID)My_UnmapViewOfFile},
                    {"kernel32.dll", "LoadLibraryA", (PVOID)My_LoadLibraryA},
                    {"kernel32.dll", "LoadLibraryW", (PVOID)My_LoadLibraryW},
                    {"kernel32.dll", "LoadLibraryExA", (PVOID)My_LoadLibraryExA},
                    {"kernel32.dll", "LoadLibraryExW", (PVOID)My_LoadLibraryExW},
                    {"kernel32.dll", "GetProcAddress", (PVOID)My_GetProcAddress},
                    {"kernel32.dll", "SetThreadContext", (PVOID)My_SetThreadContext},
                    {"kernel32.dll", "GetThreadContext", (PVOID)My_GetThreadContext},
                    {"kernel32.dll", "Wow64GetThreadContext", (PVOID)My_Wow64GetThreadContext},
                    {"kernel32.dll", "Wow64SetThreadContext", (PVOID)My_Wow64SetThreadContext},
                    {"kernel32.dll", "SuspendThread", (PVOID)My_SuspendThread},
                    {"kernel32.dll", "ResumeThread", (PVOID)My_ResumeThread},
                    {"kernel32.dll", "IsDebuggerPresent", (PVOID)My_IsDebuggerPresent},
                    {"kernel32.dll", "CheckRemoteDebuggerPresent", (PVOID)My_CheckRemoteDebuggerPresent},
                    {"kernel32.dll", "Sleep", (PVOID)My_Sleep},
                    {"kernel32.dll", "SleepEx", (PVOID)My_SleepEx},

                    // 3. Discovery & Credential Access
                    {"kernel32.dll", "OpenProcess", (PVOID)My_OpenProcess},
                    {"kernel32.dll", "OpenThread", (PVOID)My_OpenThread},
                    {"kernel32.dll", "CreateToolhelp32Snapshot", (PVOID)My_CreateToolhelp32Snapshot},
                    {"kernel32.dll", "GetSystemInfo", (PVOID)My_GetSystemInfo},
                    {"kernel32.dll", "GetNativeSystemInfo", (PVOID)My_GetNativeSystemInfo},
                    {"kernel32.dll", "GetVersionExA", (PVOID)My_GetVersionExA},
                    {"kernel32.dll", "GetVersionExW", (PVOID)My_GetVersionExW},
                    {"kernel32.dll", "GetComputerNameA", (PVOID)My_GetComputerNameA},
                    {"kernel32.dll", "GetComputerNameW", (PVOID)My_GetComputerNameW},
                    {"kernel32.dll", "GetComputerNameExA", (PVOID)My_GetComputerNameExA},
                    {"kernel32.dll", "GetComputerNameExW", (PVOID)My_GetComputerNameExW},
                    {"kernel32.dll", "GetCurrentProcess", (PVOID)My_GetCurrentProcess},
                    {"kernel32.dll", "GetCurrentThread", (PVOID)My_GetCurrentThread},
                    {"kernel32.dll", "GetCurrentProcessId", (PVOID)My_GetCurrentProcessId},
                    {"kernel32.dll", "GetCurrentThreadId", (PVOID)My_GetCurrentThreadId},

                    // 4. Command & Control / IPC
                    {"kernel32.dll", "CreateNamedPipeA", (PVOID)My_CreateNamedPipeA},
                    {"kernel32.dll", "CreateNamedPipeW", (PVOID)My_CreateNamedPipeW},
                    {"kernel32.dll", "ConnectNamedPipe", (PVOID)My_ConnectNamedPipe},
                    {"kernel32.dll", "CallNamedPipeA", (PVOID)My_CallNamedPipeA},
                    {"kernel32.dll", "CallNamedPipeW", (PVOID)My_CallNamedPipeW},
                    //{"kernel32.dll", "DuplicateHandle", (PVOID)My_DuplicateHandle},
                    //{"kernel32.dll", "CloseHandle", (PVOID)My_CloseHandle},

                    // 5. Synchronization / Timing Evasion
                    {"kernel32.dll", "WaitForSingleObject", (PVOID)My_WaitForSingleObject},
                    {"kernel32.dll", "WaitForMultipleObjects", (PVOID)My_WaitForMultipleObjects},
                    {"kernel32.dll", "WaitForSingleObjectEx", (PVOID)My_WaitForSingleObjectEx},
                    {"kernel32.dll", "WaitForMultipleObjectsEx", (PVOID)My_WaitForMultipleObjectsEx},

                    // 6. Impact
                    {"kernel32.dll", "TerminateProcess", (PVOID)My_TerminateProcess},

                    //=====================================================
                    // advapi32.dll - Final EDR Hooks (Non-File, Non-Registry)
                    //=====================================================

                    // 1. Persistence (Services)
                    { "advapi32.dll", "CreateServiceA", (PVOID)My_CreateServiceA },
                    { "advapi32.dll", "CreateServiceW", (PVOID)My_CreateServiceW },
                    { "advapi32.dll", "DeleteService", (PVOID)My_DeleteService },
                    { "advapi32.dll", "ChangeServiceConfigA", (PVOID)My_ChangeServiceConfigA },
                    { "advapi32.dll", "ChangeServiceConfigW", (PVOID)My_ChangeServiceConfigW },
                    { "advapi32.dll", "ChangeServiceConfig2A", (PVOID)My_ChangeServiceConfig2A },
                    { "advapi32.dll", "ChangeServiceConfig2W", (PVOID)My_ChangeServiceConfig2W },
                    { "advapi32.dll", "StartServiceA", (PVOID)My_StartServiceA },
                    { "advapi32.dll", "StartServiceW", (PVOID)My_StartServiceW },
                    { "advapi32.dll", "ControlService", (PVOID)My_ControlService },

                    // 2. Privilege Escalation & Credential Access
                    { "advapi32.dll", "OpenProcessToken", (PVOID)My_OpenProcessToken },
                    { "advapi32.dll", "OpenThreadToken", (PVOID)My_OpenThreadToken },
                    { "advapi32.dll", "AdjustTokenPrivileges", (PVOID)My_AdjustTokenPrivileges },
                    { "advapi32.dll", "DuplicateTokenEx", (PVOID)My_DuplicateTokenEx },
                    { "advapi32.dll", "ImpersonateLoggedOnUser", (PVOID)My_ImpersonateLoggedOnUser },
                    { "advapi32.dll", "ImpersonateNamedPipeClient", (PVOID)My_ImpersonateNamedPipeClient },
                    { "advapi32.dll", "SetThreadToken", (PVOID)My_SetThreadToken },
                    { "advapi32.dll", "LsaOpenPolicy", (PVOID)My_LsaOpenPolicy },
                    { "advapi32.dll", "LsaQueryInformationPolicy", (PVOID)My_LsaQueryInformationPolicy },
                    { "advapi32.dll", "LsaRetrievePrivateData", (PVOID)My_LsaRetrievePrivateData },

                    // 3. Defense Evasion
                    { "advapi32.dll", "ClearEventLogA", (PVOID)My_ClearEventLogA },
                    { "advapi32.dll", "ClearEventLogW", (PVOID)My_ClearEventLogW },
                    { "advapi32.dll", "LsaSetInformationPolicy", (PVOID)My_LsaSetInformationPolicy },
                    { "advapi32.dll", "AuditSetSystemPolicy", (PVOID)My_AuditSetSystemPolicy },
                    { "advapi32.dll", "SetSecurityInfo", (PVOID)My_SetSecurityInfo },
                    { "advapi32.dll", "SetNamedSecurityInfoA", (PVOID)My_SetNamedSecurityInfoA },
                    { "advapi32.dll", "SetNamedSecurityInfoW", (PVOID)My_SetNamedSecurityInfoW },

                    // 4. Discovery
                    { "advapi32.dll", "GetUserNameA", (PVOID)My_GetUserNameA },
                    { "advapi32.dll", "GetUserNameW", (PVOID)My_GetUserNameW },
                    { "advapi32.dll", "LookupAccountNameA", (PVOID)My_LookupAccountNameA },
                    { "advapi32.dll", "LookupAccountNameW", (PVOID)My_LookupAccountNameW },
                    { "advapi32.dll", "LookupAccountSidA", (PVOID)My_LookupAccountSidA },
                    { "advapi32.dll", "LookupAccountSidW", (PVOID)My_LookupAccountSidW },
                    { "advapi32.dll", "EnumServicesStatusA", (PVOID)My_EnumServicesStatusA },
                    { "advapi32.dll", "EnumServicesStatusW", (PVOID)My_EnumServicesStatusW },
                    { "advapi32.dll", "EnumServicesStatusExA", (PVOID)My_EnumServicesStatusExA },
                    { "advapi32.dll", "EnumServicesStatusExW", (PVOID)My_EnumServicesStatusExW },

                    //=====================================================
                    // ws2_32.dll - Network Communication Hooks
                    //=====================================================

                       /*
                    // 1. Connection Initiation
                    {"ws2_32.dll", "socket", (PVOID)My_socket},
                    { "ws2_32.dll", "connect", (PVOID)My_connect },
                    { "ws2_32.dll", "WSAConnect", (PVOID)My_WSAConnect },

                    // 3. DNS/Host Resolution (C&C 서버 주소 확인)
                    { "ws2_32.dll", "gethostbyname", (PVOID)My_gethostbyname },
                    { "ws2_32.dll", "getaddrinfo", (PVOID)My_getaddrinfo },
                    { "ws2_32.dll", "WSAAsyncGetHostByName", (PVOID)My_WSAAsyncGetHostByName },

                    // 4. Cleanup
                    { "ws2_32.dll", "closesocket", (PVOID)My_closesocket },

                    // 5. Raw Socket Access (네트워크 정찰/패킷 스니핑)
                    { "ws2_32.dll", "ioctlsocket", (PVOID)My_ioctlsocket },
                       

                    //=====================================================
                    // user32.dll - User Interface & Input Hooks
                    //=====================================================

                    // 1. Keylogging (키로깅)
                    { "user32.dll", "SetWindowsHookExA", (PVOID)My_SetWindowsHookExA },
                    { "user32.dll", "SetWindowsHookExW", (PVOID)My_SetWindowsHookExW },
                    { "user32.dll", "UnhookWindowsHookEx", (PVOID)My_UnhookWindowsHookEx },
                    { "user32.dll", "GetAsyncKeyState", (PVOID)My_GetAsyncKeyState },
                    { "user32.dll", "GetKeyState", (PVOID)My_GetKeyState },
                    { "user32.dll", "GetKeyboardState", (PVOID)My_GetKeyboardState },

                    // 2. Window Manipulation (윈도우 숨기기, 포그라운드 캡처)
                    { "user32.dll", "ShowWindow", (PVOID)My_ShowWindow },
                    { "user32.dll", "FindWindowA", (PVOID)My_FindWindowA },
                    { "user32.dll", "FindWindowW", (PVOID)My_FindWindowW },
                    { "user32.dll", "GetForegroundWindow", (PVOID)My_GetForegroundWindow },

                    // 3. UAC Bypass (사용자 권한 상승 우회)
                    { "user32.dll", "CreateWindowExA", (PVOID)My_CreateWindowExA },
                    { "user32.dll", "CreateWindowExW", (PVOID)My_CreateWindowExW },
                    { "user32.dll", "ShellExecuteA", (PVOID)My_ShellExecuteA },
                    { "user32.dll", "ShellExecuteW", (PVOID)My_ShellExecuteW },
                    { "user32.dll", "ShellExecuteExA", (PVOID)My_ShellExecuteExA },
                    { "user32.dll", "ShellExecuteExW", (PVOID)My_ShellExecuteExW },

                    //=====================================================
                    // gdi32.dll - Screen Capture Hooks
                    //=====================================================

                    // 1. Device Context (DC) Manipulation
                    { "gdi32.dll", "CreateDCA", (PVOID)My_CreateDCA },
                    { "gdi32.dll", "CreateDCW", (PVOID)My_CreateDCW },
                    { "gdi32.dll", "CreateCompatibleDC", (PVOID)My_CreateCompatibleDC },
                    { "gdi32.dll", "GetDC", (PVOID)My_GetDC },

                    // 2. Bitmap Creation/Copy (실제 스크린샷 데이터 생성)
                    { "gdi32.dll", "CreateCompatibleBitmap", (PVOID)My_CreateCompatibleBitmap },
                    { "gdi32.dll", "BitBlt", (PVOID)My_BitBlt },

                    //=====================================================
                    // wininet.dll - High-Level Internet Communication Hooks
                    //=====================================================

                    // 1. Internet Handle Creation
                    { "wininet.dll", "InternetOpenA", (PVOID)My_InternetOpenA },
                    { "wininet.dll", "InternetOpenW", (PVOID)My_InternetOpenW },

                    // 2. Connection & Request
                    { "wininet.dll", "InternetConnectA", (PVOID)My_InternetConnectA },
                    { "wininet.dll", "InternetConnectW", (PVOID)My_InternetConnectW },
                    { "wininet.dll", "HttpOpenRequestA", (PVOID)My_HttpOpenRequestA },
                    { "wininet.dll", "HttpOpenRequestW", (PVOID)My_HttpOpenRequestW },
                    { "wininet.dll", "HttpSendRequestA", (PVOID)My_HttpSendRequestA },
                    { "wininet.dll", "HttpSendRequestW", (PVOID)My_HttpSendRequestW },

                    // 3. Data Transfer
                    { "wininet.dll", "InternetReadFile", (PVOID)My_InternetReadFile },
                    { "wininet.dll", "InternetWriteFile", (PVOID)My_InternetWriteFile },

                    //=====================================================
                    // shell32.dll - Shell Functions Hooks
                    //=====================================================

                    // 1. Execution (파일 실행)
                    { "shell32.dll", "ShellExecuteA", (PVOID)My_ShellExecuteA },
                    { "shell32.dll", "ShellExecuteW", (PVOID)My_ShellExecuteW },
                    { "shell32.dll", "ShellExecuteExA", (PVOID)My_ShellExecuteExA },
                    { "shell32.dll", "ShellExecuteExW", (PVOID)My_ShellExecuteExW },

                    // 2. Special Folder Access (정보 수집, 지속성)
                    { "shell32.dll", "SHGetSpecialFolderPathA", (PVOID)My_SHGetSpecialFolderPathA },
                    { "shell32.dll", "SHGetSpecialFolderPathW", (PVOID)My_SHGetSpecialFolderPathW },
                    { "shell32.dll", "SHGetFolderPathA", (PVOID)My_SHGetFolderPathA },
                    { "shell32.dll", "SHGetFolderPathW", (PVOID)My_SHGetFolderPathW },

                    //=====================================================
                    // crypt32.dll - Cryptography & Certificate Hooks
                    //=====================================================
                    { "crypt32.dll", "CryptEncrypt", (PVOID)My_CryptEncrypt },
                    { "crypt32.dll", "CryptDecrypt", (PVOID)My_CryptDecrypt },
                    { "crypt32.dll", "CryptGenKey", (PVOID)My_CryptGenKey },
                    { "crypt32.dll", "CryptImportKey", (PVOID)My_CryptImportKey },
                    { "crypt32.dll", "CertOpenStore", (PVOID)My_CertOpenStore },
                    { "crypt32.dll", "CertAddCertificateContextToStore", (PVOID)My_CertAddCertificateContextToStore },
                    { "crypt32.dll", "PFXImportCertStore", (PVOID)My_PFXImportCertStore },

                    //=====================================================
                    // ole32.dll / combase.dll - COM & OLE Hooks
                    //=====================================================
                    { "ole32.dll", "CoCreateInstance", (PVOID)My_CoCreateInstance },
                    { "combase.dll", "CoCreateInstance", (PVOID)My_CoCreateInstance_combase },
                    { "ole32.dll", "CoCreateInstanceEx", (PVOID)My_CoCreateInstanceEx },
                    { "combase.dll", "CoCreateInstanceEx", (PVOID)My_CoCreateInstanceEx_combase },
                    { "ole32.dll", "CoGetObject", (PVOID)My_CoGetObject },

                    //=====================================================
                    // wintrust.dll - Trust Verification Hookss
                    //=====================================================
                    //{ "wintrust.dll", "WinVerifyTrust", (PVOID)My_WinVerifyTrust }*/
                };
            }
        }
    }
}

