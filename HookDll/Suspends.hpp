#ifndef SUSPEND_HPP
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>

namespace EDR
{
	namespace Util
	{
		namespace Suspends
		{
			inline BOOLEAN Suspend_Thread()
			{
				DWORD currentPID = GetCurrentProcessId();
				DWORD currentTID = GetCurrentThreadId();

                HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (hSnapshot == INVALID_HANDLE_VALUE) return false;

                THREADENTRY32 te32;
                te32.dwSize = sizeof(THREADENTRY32);

                if (Thread32First(hSnapshot, &te32)) {
                    do {
                        if (te32.th32OwnerProcessID == currentPID && te32.th32ThreadID != currentTID) {
                            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                            if (hThread) {
                                SuspendThread(hThread);
                                CloseHandle(hThread);
                            }
                        }
                    } while (Thread32Next(hSnapshot, &te32));
                }

                CloseHandle(hSnapshot);
                return true;
			}

            inline void Resume_Threads()
            {
                DWORD currentPID = GetCurrentProcessId();
                DWORD currentTID = GetCurrentThreadId();

                HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (hSnapshot == INVALID_HANDLE_VALUE) return;

                THREADENTRY32 te32;
                te32.dwSize = sizeof(THREADENTRY32);

                if (Thread32First(hSnapshot, &te32)) {
                    do {
                        if (te32.th32OwnerProcessID == currentPID && te32.th32ThreadID != currentTID) {
                            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                            if (hThread) {
                                ResumeThread(hThread);
                                CloseHandle(hThread);
                            }
                        }
                    } while (Thread32Next(hSnapshot, &te32));
                }

                CloseHandle(hSnapshot);
            }

		}
	}
}


#endif