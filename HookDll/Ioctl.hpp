#ifndef IOCTL2_HPP
#define IOCTL2_HPP

#include <Windows.h>
#include <devioctl.h>

#include <thread>
#include <string>
#include <iostream>

#include "timestamp.hpp"

#include "Queue.hpp"
#include "ioctlcodes.hpp"

#define IOCTL_Device_SymbolicName L"\\??\\VATEX_EVIDENTIA_EDR_AGENT"



namespace EDR
{
	namespace IOCTL
	{
        struct QUEUE_DATA
        {
            std::string JSON;
            ULONG64 timestamp;
        };

        class IoctlSender
        {
        public:
            IoctlSender() : stopFlag(false), deviceHandle(INVALID_HANDLE_VALUE) {
                deviceHandle = CreateFileW(
                    IOCTL_Device_SymbolicName,
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    NULL,
                    OPEN_EXISTING,
                    0,
                    NULL
                );
                this->Run();
            }

            ~IoctlSender() {
                Stop();
                if (deviceHandle != INVALID_HANDLE_VALUE) {
                    CloseHandle(deviceHandle);
                }
            }

            void Run() {
                stopFlag = false;
                workerThread = std::thread([this]() {
                        while (!stopFlag) {
                            auto data = queue.get(); // ºí·ÎÅ·


                            struct IOCTL_API_CALLS_Data IoctlLog;
                            RtlZeroMemory(&IoctlLog, sizeof(struct IOCTL_API_CALLS_Data));

                            IoctlLog.timestamp = data.timestamp;
                            IoctlLog.ProcessId = (HANDLE)GetCurrentProcessId();
                            memcpy(IoctlLog.Json, data.JSON.c_str(), data.JSON.length() + 1 > APIHooked_IOCTL_DATA_Json_Strlen_MaxSize ? APIHooked_IOCTL_DATA_Json_Strlen_MaxSize : data.JSON.length() + 1);

                            SendToKernel(IoctlLog);
                        }

                        while (!queue.empty())
                            queue.get();
                    }
                );
            }

            void Stop() {
                stopFlag = true;
                
                if (workerThread.joinable()) {
                    workerThread.join();
                }
            }

            void SendToQueue(const std::string& Json, const ULONG64 timestamp = EDR::Util::timestamp::Get_Real_Timestamp() ) {

                

                if (!stopFlag)
                {
                    queue.put(
                        {Json, timestamp} // struct QUEUE_ITEM
                    );
                }
                    
            }

        private:
            void SendToKernel(const IOCTL_API_CALLS_Data& data) {
                if (deviceHandle == INVALID_HANDLE_VALUE) return;

                DWORD bytesReturned = 0;
                DeviceIoControl(
                    deviceHandle,
                    IOCTL_API_CALLS,
                    (LPVOID)&data,
                    sizeof(IOCTL_API_CALLS_Data),
                    nullptr,
                    0,
                    &bytesReturned,
                    nullptr
                );
            }

            EDR::Util::Queue::Queue<struct QUEUE_DATA> queue;
            std::thread workerThread;
            std::atomic<bool> stopFlag;
            HANDLE deviceHandle;
        };
        extern IoctlSender g_IoctlSender;
	}
}

#endif