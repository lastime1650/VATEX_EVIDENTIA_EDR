#ifndef API_HOOK_HANDLER_HPP
#define API_HOOK_HANDLER_HPP

#define WIN32_LEAN_AND_MEAN
// =====================================================
// 순서 변경: ntsecapi.h를 Windows.h 보다 먼저 포함합니다.
// =====================================================
// 중복 정의 방지: ntstatus.h 포함 전에 정의
#define WIN32_NO_STATUS

#include <Windows.h>
#include <ntsecapi.h>
//#include <winternl.h> - STIRNG, UNICODE_STRING 관련 충돌이 <<ntsecapi.h>> 와 발생함.

#include <shellapi.h>
#include <wininet.h>
#include <winbase.h>
#include <winevt.h>
#include <sddl.h>
#include <Aclapi.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
#include <wincrypt.h>
#include <Unknwn.h>

#include "API_HOOK_STRUCTS.hpp"

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // PSECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // PSecurityQualityOfService
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;          \
}
typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0,
    ThreadTimes = 1,
    ThreadPriority = 2,
    ThreadBasePriority = 3,
    ThreadAffinityMask = 4,
    ThreadImpersonationToken = 5,
    ThreadDescriptorTableEntry = 6,
    ThreadEnableAlignmentFaultFixup = 7,
    ThreadEventPair_Reusable = 8,
    ThreadQuerySetWin32StartAddress = 9,
    ThreadZeroTlsCell = 10,
    ThreadPerformanceCount = 11,
    ThreadAmILastThread = 12,
    ThreadIdealProcessor = 13,
    ThreadPriorityBoost = 14,
    ThreadSetTlsArrayAddress = 15,
    ThreadIsIoPending = 16,
    ThreadHideFromDebugger = 17,
    ThreadBreakOnTermination = 18,
    MaxThreadInfoClass = 19
} THREADINFOCLASS;
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessQuotaLimits = 1,
    ProcessIoCounters = 2,
    ProcessVmCounters = 3,
    ProcessTimes = 4,
    ProcessBasePriority = 5,
    ProcessRaisePriority = 6,
    ProcessDebugPort = 7,
    ProcessExceptionPort = 8,
    ProcessAccessToken = 9,
    ProcessLdtInformation = 10,
    ProcessLdtSize = 11,
    ProcessDefaultHardErrorMode = 12,
    ProcessIoPortHandlers = 13,
    ProcessPooledUsageAndLimits = 14,
    ProcessWorkingSetWatch = 15,
    ProcessUserModeIOPL = 16,
    ProcessEnableAlignmentFaultFixup = 17,
    ProcessPriorityClass = 18,
    ProcessWx86Information = 19,
    ProcessHandleCount = 20,
    ProcessAffinityMask = 21,
    ProcessPriorityBoost = 22,
    ProcessDeviceMap = 23,
    ProcessSessionInformation = 24,
    ProcessForegroundInformation = 25,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessLUIDDeviceMapsEnabled = 28,
    ProcessBreakOnTermination = 29,
    ProcessDebugObjectHandle = 30,
    ProcessDebugFlags = 31,
    ProcessHandleTracing = 32,
    ProcessIoPriority = 33,
    ProcessExecuteFlags = 34,
    MaxProcessInfoClass = 35
} PROCESSINFOCLASS;
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemObsolete0 = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeperation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    MaxSystemInfoClass = 44
} SYSTEM_INFORMATION_CLASS;
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectAllInformation = 3,
    ObjectDataInformation = 4,
    MaxObjectInfoClass = 5
} OBJECT_INFORMATION_CLASS;


#include <string>
#include <ostream>
#include <map>
#include <iostream>
#include <sstream>    // std::stringstream
#include <iomanip>    // std::hex, std::setw, std::setfill
#include <vector>

#include "Ioctl.hpp"

namespace EDR
{
	namespace Util
	{
		namespace API_Hook
		{
            namespace Handlers
            {
                namespace Helper
                {
                    //=====================================================
                // 1. 기본 타입 변환
                //=====================================================

                // 포인터(PVOID, HANDLE 등)를 16진수 문자열로 변환
                    inline std::string PtrToString(const void* ptr)
                    {
                        if (ptr == nullptr) {
                            return "NULL";
                        }
                        std::stringstream ss;
                        ss << "0x" << std::hex << std::setw(sizeof(ptr) * 2) << std::setfill('0') << reinterpret_cast<uintptr_t>(ptr);
                        return ss.str();
                    }

                    // 부호 없는 64비트 정수를 16진수 문자열로 변환
                    inline std::string Ulong64ToHexString(UINT64 val)
                    {
                        std::stringstream ss;
                        ss << "0x" << std::hex << val;
                        return ss.str();
                    }

                    // DWORD/ULONG을 16진수 문자열로 변환
                    inline std::string DwordToHexString(DWORD val)
                    {
                        std::stringstream ss;
                        ss << "0x" << std::hex << val;
                        return ss.str();
                    }

                    //=====================================================
                    // 2. 문자열 타입 변환
                    //=====================================================

                    // LPCWSTR (와이드 문자열)을 UTF-8 std::string으로 변환
                    inline std::string WstrToString(LPCWSTR wstr)
                    {
                        if (wstr == nullptr) {
                            return "[null]";
                        }
                        if (wcslen(wstr) == 0) {
                            return "[empty]";
                        }
                        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
                        if (size_needed == 0) {
                            return "[conversion_failed]";
                        }
                        std::string strTo(size_needed, 0);
                        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], -1, &strTo[0], size_needed, NULL, NULL);
                        strTo.pop_back(); // Remove the null terminator
                        return strTo;
                    }

                    // LPCSTR (ANSI 문자열)을 std::string으로 변환
                    inline std::string AstrToString(LPCSTR astr)
                    {
                        if (astr == nullptr) {
                            return "[null]";
                        }
                        if (strlen(astr) == 0) {
                            return "[empty]";
                        }
                        return std::string(astr);
                    }

                    // UNICODE_STRING 구조체를 std::string으로 변환
                    inline std::string UnicodeStringToString(const UNICODE_STRING& us)
                    {
                        if (us.Buffer == nullptr || us.Length == 0) {
                            return "[empty]";
                        }
                        int size_needed = WideCharToMultiByte(CP_UTF8, 0, us.Buffer, us.Length / sizeof(WCHAR), NULL, 0, NULL, NULL);
                        if (size_needed == 0) {
                            return "[conversion_failed]";
                        }
                        std::string strTo(size_needed, 0);
                        WideCharToMultiByte(CP_UTF8, 0, us.Buffer, us.Length / sizeof(WCHAR), &strTo[0], size_needed, NULL, NULL);
                        return strTo;
                    }

                    //=====================================================
                    // 3. Windows 구조체 멤버 변환
                    //=====================================================

                    // OBJECT_ATTRIBUTES 구조체의 ObjectName을 std::string으로 변환
                    inline std::string ObjectAttributesToString(const OBJECT_ATTRIBUTES* objAttr)
                    {
                        if (objAttr == nullptr || objAttr->ObjectName == nullptr) {
                            return "[null_obj_attr]";
                        }
                        return UnicodeStringToString(*(objAttr->ObjectName));
                    }

                    //=====================================================
                    // 4. 플래그 및 열거형 변환 (예시)
                    //=====================================================
                    // 이런 함수들은 필요에 따라 계속 추가해나가야 합니다.

                    // 프로세스 생성 플래그(dwCreationFlags)를 문자열로 변환
                    inline std::string CreationFlagsToString(DWORD flags)
                    {
                        std::vector<std::string> flagStrings;
                        if (flags == 0) return "0x0";
                        if (flags & CREATE_SUSPENDED) flagStrings.push_back("CREATE_SUSPENDED");
                        if (flags & CREATE_NEW_CONSOLE) flagStrings.push_back("CREATE_NEW_CONSOLE");
                        if (flags & CREATE_NO_WINDOW) flagStrings.push_back("CREATE_NO_WINDOW");
                        if (flags & DETACHED_PROCESS) flagStrings.push_back("DETACHED_PROCESS");
                        if (flags & EXTENDED_STARTUPINFO_PRESENT) flagStrings.push_back("EXTENDED_STARTUPINFO_PRESENT");
                        // ... 기타 필요한 플래그 추가 ...

                        std::string result;
                        for (size_t i = 0; i < flagStrings.size(); ++i) {
                            result += flagStrings[i];
                            if (i < flagStrings.size() - 1) {
                                result += " | ";
                            }
                        }
                        return result.empty() ? DwordToHexString(flags) : result;
                    }

                    // 메모리 보호 플래그(flProtect)를 문자열로 변환
                    inline std::string ProtectFlagsToString(DWORD flags)
                    {
                        std::vector<std::string> flagStrings;
                        if (flags == 0) return "0x0";
                        if (flags & PAGE_EXECUTE) flagStrings.push_back("PAGE_EXECUTE");
                        if (flags & PAGE_EXECUTE_READ) flagStrings.push_back("PAGE_EXECUTE_READ");
                        if (flags & PAGE_EXECUTE_READWRITE) flagStrings.push_back("PAGE_EXECUTE_READWRITE");
                        if (flags & PAGE_EXECUTE_WRITECOPY) flagStrings.push_back("PAGE_EXECUTE_WRITECOPY");
                        if (flags & PAGE_NOACCESS) flagStrings.push_back("PAGE_NOACCESS");
                        if (flags & PAGE_READONLY) flagStrings.push_back("PAGE_READONLY");
                        if (flags & PAGE_READWRITE) flagStrings.push_back("PAGE_READWRITE");
                        if (flags & PAGE_WRITECOPY) flagStrings.push_back("PAGE_WRITECOPY");
                        if (flags & PAGE_GUARD) flagStrings.push_back("PAGE_GUARD");
                        if (flags & PAGE_NOCACHE) flagStrings.push_back("PAGE_NOCACHE");
                        if (flags & PAGE_WRITECOMBINE) flagStrings.push_back("PAGE_WRITECOMBINE");

                        std::string result;
                        for (size_t i = 0; i < flagStrings.size(); ++i) {
                            result += flagStrings[i];
                            if (i < flagStrings.size() - 1) {
                                result += " | ";
                            }
                        }
                        return result.empty() ? DwordToHexString(flags) : result;
                    }

                    // GUID to String 
                    inline std::string GuidToString(const GUID& guid) {
                        wchar_t guid_string[40];
                        if (StringFromGUID2(guid, guid_string, 40) > 0) {
                            return Helper::WstrToString(guid_string);
                        }
                        return "[invalid_guid]";
                    }


                    /*
                    // sockaddr 구조체를 "IP:PORT" 형태의 문자열로 변환
                    inline std::string SockAddrToString(const struct sockaddr* addr)
                    {
                        if (!addr) {
                            return "[null_addr]";
                        }

                        WCHAR ipString[INET6_ADDRSTRLEN] = { 0 };
                        DWORD port = 0;

                        if (addr->sa_family == AF_INET) {
                            struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr;
                            if (InetNtopW(AF_INET, &ipv4->sin_addr, ipString, INET6_ADDRSTRLEN)) {
                                port = ntohs(ipv4->sin_port);
                            }
                            else {
                                return "[inet_ntop_failed]";
                            }
                        }
                        else if (addr->sa_family == AF_INET6) {
                            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addr;
                            if (InetNtopW(AF_INET6, &ipv6->sin6_addr, ipString, INET6_ADDRSTRLEN)) {
                                port = ntohs(ipv6->sin6_port);
                            }
                            else {
                                return "[inet_ntop_failed]";
                            }
                        }
                        else {
                            return "[family:" + std::to_string(addr->sa_family) + "]";
                        }

                        return WstrToString(ipString) + ":" + std::to_string(port);
                    }*/

                }

                /*
                    handler
                */
                extern "C" {

                    //=====================================================
                    // ntdll.dll Handlerssd
                    //=====================================================
                    NTSTATUS NTAPI My_NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
                    NTSTATUS NTAPI My_NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
                    NTSTATUS NTAPI My_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
                    NTSTATUS NTAPI My_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
                    NTSTATUS NTAPI My_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
                    NTSTATUS NTAPI My_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
                    NTSTATUS NTAPI My_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
                    NTSTATUS NTAPI My_NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
                    NTSTATUS NTAPI My_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
                    NTSTATUS NTAPI My_NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
                    NTSTATUS NTAPI My_NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
                    NTSTATUS NTAPI My_NtGetContextThread(HANDLE ThreadHandle, PCONTEXT pContext);
                    NTSTATUS NTAPI My_NtSetContextThread(HANDLE ThreadHandle, PCONTEXT pContext);
                    NTSTATUS NTAPI My_NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
                    NTSTATUS NTAPI My_NtOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle);
                    NTSTATUS NTAPI My_NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);
                    NTSTATUS NTAPI My_NtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle);
                    NTSTATUS NTAPI My_NtFilterToken(HANDLE ExistingTokenHandle, ULONG Flags, PVOID SidsToDisable, PVOID PrivilegesToDelete, PVOID RestrictedSids, PHANDLE NewTokenHandle);
                    NTSTATUS NTAPI My_NtImpersonateThread(HANDLE ServerThreadHandle, HANDLE ClientThreadHandle, PSECURITY_QUALITY_OF_SERVICE SecurityQos);
                    NTSTATUS NTAPI My_NtImpersonateClientOfPort(HANDLE PortHandle, PVOID Message);
                    NTSTATUS NTAPI My_NtLoadDriver(PUNICODE_STRING DriverServiceName);
                    NTSTATUS NTAPI My_NtUnloadDriver(PUNICODE_STRING DriverServiceName);
                    NTSTATUS NTAPI My_NtCreateWnfStateName(PVOID p1, PVOID p2, PVOID p3, PVOID p4, PVOID p5, PVOID p6, PVOID p7);
                    NTSTATUS NTAPI My_NtUpdateWnfStateData(PVOID p1, PVOID p2, PVOID p3, PVOID p4, PVOID p5, PVOID p6);
                    NTSTATUS NTAPI My_NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
                    NTSTATUS NTAPI My_NtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
                    NTSTATUS NTAPI My_NtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle);
                    NTSTATUS NTAPI My_NtSetInformationDebugObject(HANDLE DebugObjectHandle, ULONG DebugObjectInformationClass, PVOID DebugInformation, ULONG DebugInformationLength, PULONG ReturnLength);
                    NTSTATUS NTAPI My_NtSystemDebugControl(DWORD ControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
                    NTSTATUS NTAPI My_NtClose(HANDLE Handle);
                    NTSTATUS NTAPI My_NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
                    NTSTATUS NTAPI My_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
                    NTSTATUS NTAPI My_NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
                    NTSTATUS NTAPI My_NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, DWORD MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
                    NTSTATUS NTAPI My_NtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
                    NTSTATUS NTAPI My_NtQuerySystemEnvironmentValue(PUNICODE_STRING VariableName, PWSTR Value, ULONG ValueLength, PULONG ReturnLength);
                    NTSTATUS NTAPI My_NtQuerySystemEnvironmentValueEx(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, PULONG ValueLength, PULONG Attributes);
                    NTSTATUS NTAPI My_LdrLoadDll(PWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle);
                    NTSTATUS NTAPI My_LdrGetProcedureAddress(PVOID DllHandle, PSTRING ProcedureName, ULONG ProcedureNumber, PVOID* ProcedureAddress);

                    //=====================================================
                    // kernel32.dll Handlers
                    //=====================================================
                    BOOL WINAPI My_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
                    BOOL WINAPI My_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
                    BOOL WINAPI My_CreateProcessAsUserA(HANDLE hToken, LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
                    BOOL WINAPI My_CreateProcessAsUserW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
                    HANDLE WINAPI My_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
                    HANDLE WINAPI My_CreateRemoteThreadEx(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId);
                    UINT WINAPI My_WinExec(LPCSTR lpCmdLine, UINT uCmdShow);
                    BOOL WINAPI My_QueueUserWorkItem(LPTHREAD_START_ROUTINE Function, PVOID Context, ULONG Flags);
                    BOOL WINAPI My_CreateTimerQueueTimer(PHANDLE phNewTimer, HANDLE TimerQueue, WAITORTIMERCALLBACK Callback, PVOID Parameter, DWORD DueTime, DWORD Period, ULONG Flags);
                    VOID WINAPI My_ExitProcess(UINT uExitCode);
                    VOID WINAPI My_ExitThread(DWORD dwExitCode);
                    LPVOID WINAPI My_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
                    LPVOID WINAPI My_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
                    BOOL WINAPI My_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
                    BOOL WINAPI My_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
                    BOOL WINAPI My_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
                    SIZE_T WINAPI My_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
                    SIZE_T WINAPI My_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
                    BOOL WINAPI My_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
                    LPVOID WINAPI My_MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
                    LPVOID WINAPI My_MapViewOfFileEx(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress);
                    BOOL WINAPI My_UnmapViewOfFile(LPCVOID lpBaseAddress);
                    HMODULE WINAPI My_LoadLibraryA(LPCSTR lpLibFileName);
                    HMODULE WINAPI My_LoadLibraryW(LPCWSTR lpLibFileName);
                    HMODULE WINAPI My_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
                    HMODULE WINAPI My_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
                    FARPROC WINAPI My_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
                    BOOL WINAPI My_SetThreadContext(HANDLE hThread, const CONTEXT* lpContext);
                    BOOL WINAPI My_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
                    BOOL WINAPI My_Wow64GetThreadContext(HANDLE hThread, PWOW64_CONTEXT lpContext);
                    BOOL WINAPI My_Wow64SetThreadContext(HANDLE hThread, const WOW64_CONTEXT* lpContext);
                    DWORD WINAPI My_SuspendThread(HANDLE hThread);
                    DWORD WINAPI My_ResumeThread(HANDLE hThread);
                    BOOL WINAPI My_IsDebuggerPresent();
                    BOOL WINAPI My_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent);
                    VOID WINAPI My_Sleep(DWORD dwMilliseconds);
                    DWORD WINAPI My_SleepEx(DWORD dwMilliseconds, BOOL bAlertable);
                    HANDLE WINAPI My_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
                    HANDLE WINAPI My_OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
                    HANDLE WINAPI My_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
                    VOID WINAPI My_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
                    VOID WINAPI My_GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo);
                    BOOL WINAPI My_GetVersionExA(LPOSVERSIONINFOA lpVersionInformation);
                    BOOL WINAPI My_GetVersionExW(LPOSVERSIONINFOW lpVersionInformation);
                    BOOL WINAPI My_GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize);
                    BOOL WINAPI My_GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize);
                    BOOL WINAPI My_GetComputerNameExA(COMPUTER_NAME_FORMAT NameType, LPSTR lpBuffer, LPDWORD nSize);
                    BOOL WINAPI My_GetComputerNameExW(COMPUTER_NAME_FORMAT NameType, LPWSTR lpBuffer, LPDWORD nSize);
                    HANDLE WINAPI My_GetCurrentProcess();
                    HANDLE WINAPI My_GetCurrentThread();
                    DWORD WINAPI My_GetCurrentProcessId();
                    DWORD WINAPI My_GetCurrentThreadId();
                    HANDLE WINAPI My_CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
                    HANDLE WINAPI My_CreateNamedPipeW(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
                    BOOL WINAPI My_ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
                    BOOL WINAPI My_CallNamedPipeA(LPCSTR lpNamedPipeName, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesRead, DWORD nTimeOut);
                    BOOL WINAPI My_CallNamedPipeW(LPCWSTR lpNamedPipeName, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesRead, DWORD nTimeOut);
                    BOOL WINAPI My_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
                    BOOL WINAPI My_CloseHandle(HANDLE hObject);
                    DWORD WINAPI My_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
                    DWORD WINAPI My_WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);
                    DWORD WINAPI My_WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable);
                    DWORD WINAPI My_WaitForMultipleObjectsEx(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds, BOOL bAlertable);
                    BOOL WINAPI My_TerminateProcess(HANDLE hProcess, UINT uExitCode);

                    //=====================================================
                    // advapi32.dll Handlers
                    //=====================================================
                    SC_HANDLE WINAPI My_CreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword);
                    SC_HANDLE WINAPI My_CreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword);
                    BOOL WINAPI My_DeleteService(SC_HANDLE hService);
                    BOOL WINAPI My_ChangeServiceConfigA(SC_HANDLE hService, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword, LPCSTR lpDisplayName);
                    BOOL WINAPI My_ChangeServiceConfigW(SC_HANDLE hService, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword, LPCWSTR lpDisplayName);
                    BOOL WINAPI My_ChangeServiceConfig2A(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo);
                    BOOL WINAPI My_ChangeServiceConfig2W(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo);
                    BOOL WINAPI My_StartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR* lpServiceArgVectors);
                    BOOL WINAPI My_StartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors);
                    BOOL WINAPI My_ControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
                    BOOL WINAPI My_OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
                    BOOL WINAPI My_OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
                    BOOL WINAPI My_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
                    BOOL WINAPI My_DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
                    BOOL WINAPI My_ImpersonateLoggedOnUser(HANDLE hToken);
                    BOOL WINAPI My_ImpersonateNamedPipeClient(HANDLE hNamedPipe);
                    BOOL WINAPI My_SetThreadToken(PHANDLE Thread, HANDLE Token);
                    NTSTATUS NTAPI My_LsaOpenPolicy(LSA_HANDLE SystemName, POBJECT_ATTRIBUTES ObjectAttributes, ACCESS_MASK DesiredAccess, PLSA_HANDLE PolicyHandle);
                    NTSTATUS NTAPI My_LsaQueryInformationPolicy(LSA_HANDLE PolicyHandle, POLICY_INFORMATION_CLASS InformationClass, PVOID* Buffer);
                    NTSTATUS NTAPI My_LsaRetrievePrivateData(LSA_HANDLE PolicyHandle, PUNICODE_STRING KeyName, PVOID* PrivateData);
                    BOOL WINAPI My_ClearEventLogA(HANDLE hEventLog, LPCSTR lpBackupFileName);
                    BOOL WINAPI My_ClearEventLogW(HANDLE hEventLog, LPCWSTR lpBackupFileName);
                    NTSTATUS NTAPI My_LsaSetInformationPolicy(LSA_HANDLE, POLICY_INFORMATION_CLASS, PVOID);
                    NTSTATUS NTAPI My_AuditSetSystemPolicy(PVOID, ULONG);
                    DWORD WINAPI My_SetSecurityInfo(HANDLE handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID psidOwner, PSID psidGroup, PACL pDacl, PACL pSacl);
                    DWORD WINAPI My_SetNamedSecurityInfoA(LPSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID psidOwner, PSID psidGroup, PACL pDacl, PACL pSacl);
                    DWORD WINAPI My_SetNamedSecurityInfoW(LPWSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID psidOwner, PSID psidGroup, PACL pDacl, PACL pSacl);
                    BOOL WINAPI My_GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer);
                    BOOL WINAPI My_GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer);
                    BOOL WINAPI My_LookupAccountNameA(LPCSTR lpSystemName, LPCSTR lpAccountName, PSID Sid, LPDWORD cbSid, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
                    BOOL WINAPI My_LookupAccountNameW(LPCWSTR lpSystemName, LPCWSTR lpAccountName, PSID Sid, LPDWORD cbSid, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
                    BOOL WINAPI My_LookupAccountSidA(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
                    BOOL WINAPI My_LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
                    BOOL WINAPI My_EnumServicesStatusA(SC_HANDLE hSCManager, DWORD dwServiceType, DWORD dwServiceState, LPENUM_SERVICE_STATUSA lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle);
                    BOOL WINAPI My_EnumServicesStatusW(SC_HANDLE hSCManager, DWORD dwServiceType, DWORD dwServiceState, LPENUM_SERVICE_STATUSW lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle);
                    BOOL WINAPI My_EnumServicesStatusExA(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName);
                    BOOL WINAPI My_EnumServicesStatusExW(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCWSTR pszGroupName);

                    //=====================================================
                    // ws2_32.dll Handlers
                    //=====================================================
                    /*
                    SOCKET WSAAPI My_socket(int af, int type, int protocol);
                    int WSAAPI My_connect(SOCKET s, const struct sockaddr* name, int namelen);
                    int WSAAPI My_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
                    struct hostent* WSAAPI My_gethostbyname(const char* name);
                    int WSAAPI My_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult);
                    HANDLE WSAAPI My_WSAAsyncGetHostByName(HWND hWnd, u_int wMsg, const char* name, char* buf, int buflen);
                    int WSAAPI My_closesocket(SOCKET s);
                    int WSAAPI My_ioctlsocket(SOCKET s, long cmd, u_long* argp); */

                    //=====================================================
                    // user32.dll Handlers
                    //=====================================================
                    HHOOK WINAPI My_SetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);
                    HHOOK WINAPI My_SetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);
                    BOOL WINAPI My_UnhookWindowsHookEx(HHOOK hhk);
                    SHORT WINAPI My_GetAsyncKeyState(int vKey);
                    SHORT WINAPI My_GetKeyState(int nVirtKey);
                    BOOL WINAPI My_GetKeyboardState(PBYTE lpKeyState);
                    BOOL WINAPI My_ShowWindow(HWND hWnd, int nCmdShow);
                    HWND WINAPI My_FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName);
                    HWND WINAPI My_FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName);
                    HWND WINAPI My_GetForegroundWindow();
                    HWND WINAPI My_CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
                    HWND WINAPI My_CreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);

                    //=====================================================
                    // gdi32.dll Handlers
                    //=====================================================
                    HDC WINAPI My_CreateDCA(LPCSTR pwszDriver, LPCSTR pwszDevice, LPCSTR pszPort, const DEVMODEA* pdm);
                    HDC WINAPI My_CreateDCW(LPCWSTR pwszDriver, LPCWSTR pwszDevice, LPCWSTR pszPort, const DEVMODEW* pdm);
                    HDC WINAPI My_CreateCompatibleDC(HDC hdc);
                    HDC WINAPI My_GetDC(HWND hWnd);
                    HBITMAP WINAPI My_CreateCompatibleBitmap(HDC hdc, int cx, int cy);
                    BOOL WINAPI My_BitBlt(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop);
                    //BOOL WINAPI My_StretchBlt(HDC hdcDest, int xDest, int yDest, int wDest, int hDest, HDC hdcSrc, int xSrc, int ySrc, int wSrc, int hSrc, DWORD rop);
                    //int WINAPI My_GetDIBits(HDC hdc, HBITMAP hbm, UINT start, UINT cLines, LPVOID lpvBits, LPBITMAPINFO lpbmi, UINT usage);

                    //=====================================================
                    // wininet.dll Handlers
                    //=====================================================
                    HINTERNET WINAPI My_InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
                    HINTERNET WINAPI My_InternetOpenW(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags);
                    HINTERNET WINAPI My_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
                    HINTERNET WINAPI My_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
                    HINTERNET WINAPI My_HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
                    HINTERNET WINAPI My_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
                    BOOL WINAPI My_HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
                    BOOL WINAPI My_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
                    BOOL WINAPI My_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
                    BOOL WINAPI My_InternetWriteFile(HINTERNET hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);

                    //=====================================================
                    // shell32.dll Handlers
                    //=====================================================
                    HINSTANCE WINAPI My_ShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd);
                    HINSTANCE WINAPI My_ShellExecuteW(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd);
                    BOOL WINAPI My_ShellExecuteExA(SHELLEXECUTEINFOA* pExecInfo);
                    BOOL WINAPI My_ShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo);
                    HRESULT STDAPICALLTYPE My_SHGetSpecialFolderPathA(HWND hwnd, LPSTR pszPath, int csidl, BOOL fCreate);
                    HRESULT STDAPICALLTYPE My_SHGetSpecialFolderPathW(HWND hwnd, LPWSTR pszPath, int csidl, BOOL fCreate);
                    HRESULT STDAPICALLTYPE My_SHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPSTR pszPath);
                    HRESULT STDAPICALLTYPE My_SHGetFolderPathW(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPWSTR pszPath);

                    //=====================================================
                    // crypt32.dll Handlers
                    //=====================================================
                    BOOL WINAPI My_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen);
                    BOOL WINAPI My_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen);
                    BOOL WINAPI My_CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey);
                    BOOL WINAPI My_CryptImportKey(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey);
                    HCERTSTORE WINAPI My_CertOpenStore(LPCSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV_LEGACY hCryptProv, DWORD dwFlags, const void* pvPara);
                    BOOL WINAPI My_CertAddCertificateContextToStore(HCERTSTORE hCertStore, PCCERT_CONTEXT pCertContext, DWORD dwAddDisposition, PCCERT_CONTEXT* ppStoreContext);
                    HCERTSTORE WINAPI My_PFXImportCertStore(CRYPT_DATA_BLOB* pPFX, LPCWSTR szPassword, DWORD dwFlags);

                    //=====================================================
                    // ole32.dll / combase.dll Handlers
                    //=====================================================
                    HRESULT STDAPICALLTYPE My_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv);
                    HRESULT STDAPICALLTYPE My_CoCreateInstance_combase(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv);
                    HRESULT STDAPICALLTYPE My_CoCreateInstanceEx(REFCLSID rclsid, IUnknown* punkOuter, DWORD dwClsCtx, COSERVERINFO* pServerInfo, DWORD dwCount, MULTI_QI* pResults);
                    HRESULT STDAPICALLTYPE My_CoCreateInstanceEx_combase(REFCLSID rclsid, IUnknown* punkOuter, DWORD dwClsCtx, COSERVERINFO* pServerInfo, DWORD dwCount, MULTI_QI* pResults);
                    HRESULT STDAPICALLTYPE My_CoGetObject(LPCWSTR pszName, BIND_OPTS* pBindOptions, REFIID riid, void** ppv);

                    //=====================================================
                    // wintrust.dll Handlers
                    //=====================================================
                    LONG WINAPI My_WinVerifyTrust(HWND hwnd, GUID* pgActionID, LPVOID pWVTData);
                }

                
                // 1. 원시적 API 후킹 등록 구조체
                struct RAW_API_HOOK
                {
                    const char* ModuleName;   // "ntdll.dll", "kernel32.dll", ...
                    const char* FunctionName; // "NtCreateFile", "CreateFileW", ...
                    PVOID Handler;            // 후킹할 함수 포인터
                };
                extern std::vector<RAW_API_HOOK> g_API_Hooks;

                

            }
		}
	}
}

#endif