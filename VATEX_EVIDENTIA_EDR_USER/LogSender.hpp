#ifndef LOGSENDER_H
#define LOGSENDER_H

#include "Util.hpp"

namespace EDR
{
	namespace LogSender
	{
        namespace Windows
        {
            class LogSender
            {
            public:
                LogSender(EDR::Util::Kafka::Kafka& Kafka, std::string AgentID) : Kafka(Kafka), AgentID(AgentID) {}
                ~LogSender() = default;

                // 프로세스 생성
                void Send_Log_Process_Create(

                    std::string SessionID,
                    std::string root_SessionID,
                    std::string parent_SessionID,

                    std::string SID,
                    std::string Username,
					std::string OsVersion,

                    HANDLE pid,
                    std::string self_exe_path,
                    ULONG64 self_exe_file_size,
                    std::string self_exe_bin_sha256,

                    HANDLE ppid,
                    std::string parent_exe_path,
                    ULONG64 parent_exe_file_size,
                    std::string parent_exe_bin_sha256,

                    std::string CommandLine,

					ULONG64 nano_timestamp
                );

                // 프로세스 제거
                void Send_Log_Process_Remove(

                    std::string SessionID,
                    std::string root_SessionID,
                    std::string parent_SessionID,

                    std::string OsVersion,

                    HANDLE pid,

                    ULONG64 nano_timestamp
                );

                //네트워크
                void Send_Log_Network(

                    std::string SessionID,
                    std::string root_SessionID,
                    std::string parent_SessionID,

                    std::string OsVersion,
                    HANDLE pid,
                    std::string interface_name,
                    std::string ipSrc,
                    ULONG32 portSrc,
                    std::string ipDest,
                    ULONG32 portDest,
                    BOOLEAN is_INGRESS,
                    ULONG32 packetSize,
                    std::string protocol,
                    ULONG64 nano_timestamp
                );

                /*
                    파일시스템
                */
                void Send_Log_FileSystem(

                    std::string SessionID,
                    std::string root_SessionID,
                    std::string parent_SessionID,

                    std::string OsVersion,
                    HANDLE pid,
                    std::string Action,
                    std::string FilePath,
                    std::string FileSHA256, // Optional
                    ULONG64 filesize,
                    ULONG64 nano_timestamp
                );

                /*
                    이미지로드
                */
                void Send_Log_ImageLoad(

                    std::string SessionID,
                    std::string root_SessionID,
                    std::string parent_SessionID,

                    std::string OsVersion,
                    HANDLE pid,
                    std::string FilePath,
                    ULONG64 filesize,
					std::string file_sha256,
                    ULONG64 nano_timestamp
                );
                
                /*
                    프로세스 접근
                */
                void Send_Log_ProcessAccess(

                    std::string SessionID,
                    std::string root_SessionID,
                    std::string parent_SessionID,

                    std::string OsVersion,
                    HANDLE pid,

                    std::string CreateHandle,
                    HANDLE Target_ProcessId,
                    std::string TargetProcess_Path,
                    std::vector < std::string >& DesiredAccess,
                    ULONG64 nano_timestamp
                );

            private:
                EDR::Util::Kafka::Kafka& Kafka;
                std::string AgentID;
            };
        }
	}
}


#endif