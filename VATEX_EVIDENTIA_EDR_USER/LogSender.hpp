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

                // 단순 로그 전송
                void Send_Log(
                    const json& log
                );

                // 프로세스 생성
                void Send_Log_Process_Create(

                    const std::string& SessionID,
                    const std::string& root_SessionID,
                    const std::string& parent_SessionID,

                    const std::string& SID,
                    const std::string& Username,
                    const std::string& OsVersion,

                    const HANDLE& pid,
                    const std::string& self_exe_path,
                    const ULONG64& self_exe_file_size,
                    const std::string& self_exe_bin_sha256,

                    const HANDLE& ppid,
                    const std::string& parent_exe_path,
                    const ULONG64& parent_exe_file_size,
                    const std::string& parent_exe_bin_sha256,

                    const std::string& CommandLine,

                    const ULONG64& nano_timestamp
                );

                // 프로세스 제거
                void Send_Log_Process_Remove(

                    const std::string& SessionID,
                    const std::string& root_SessionID,
                    const std::string& parent_SessionID,

                    const std::string& OsVersion,

                    const HANDLE& pid,

                    const ULONG64& nano_timestamp
                );

                void Send_Log_Network(
                    const std::string& SessionID,
                    const std::string& root_SessionID,
                    const std::string& parent_SessionID,

                    const std::string& OsVersion,
                    const HANDLE pid,
                    const ULONG32 interface_index,
                    const std::string& macSrc,
                    const std::string& macDest,
                    const std::string& ipSrc,
                    const ULONG32 portSrc,
                    const std::string& ipDest,
                    const ULONG32 portDest,
                    const BOOLEAN is_INGRESS,
                    const ULONG32 packetSize,
                    const std::string& protocol,
                    const ULONG64 nano_timestamp,

                    const std::string& PacketSessionID,
                    const ULONG64 first_seen_nano_timestamp,
                    const ULONG64 last_seen_nano_timestamp
                );

                /*
                    파일시스템
                */
                void Send_Log_FileSystem(
                    const std::string& SessionID,
                    const std::string& root_SessionID,
                    const std::string& parent_SessionID,

                    const std::string& OsVersion,
                    const HANDLE pid,
                    const std::string& Action,
                    const std::string& FilePath,
                    const std::string& FileSHA256, // Optional
                    const ULONG64 filesize,
                    const std::string& filerename,
                    const ULONG64 nano_timestamp
                );

                /*
                    이미지로드
                */
                void Send_Log_ImageLoad(

                    const std::string& SessionID,
                    const std::string& root_SessionID,
                    const std::string& parent_SessionID,

                    const std::string& OsVersion,
                    const HANDLE& pid,
                    const std::string& FilePath,
                    const ULONG64& filesize,
                    const std::string& file_sha256,
                    const ULONG64& nano_timestamp
                );
                
                /*
                    프로세스 접근
                */
                void Send_Log_ProcessAccess(

                    const std::string& SessionID,
                    const std::string& root_SessionID,
                    const std::string& parent_SessionID,

                    const std::string& OsVersion,
                    const HANDLE& pid,

                    const std::string& CreateHandle,
                    const HANDLE& Target_ProcessId,

                    const std::vector < std::string >& DesiredAccess,
                    const ULONG64& nano_timestamp
                );

                /*
                    레지스트리
                */
                void Send_Log_Registry(

                    std::string SessionID,
                    std::string root_SessionID,
                    std::string parent_SessionID,

                    std::string OsVersion,
                    HANDLE pid,

                    std::string RegistryKeyClass,
                    std::string Target_Name,

                    ULONG64 nano_timestamp
                );
                void Send_Log_Registry(

                    std::string SessionID,
                    std::string root_SessionID,
                    std::string parent_SessionID,

                    std::string OsVersion,
                    HANDLE pid,

                    std::string RegistryKeyClass,
                    std::string Target_Name,
                    std::string OldName,
                    std::string NewName,

                    ULONG64 nano_timestamp
                );

                /*
                    API 후킹
                */
                void Send_Log_APICall(
                    std::string SessionID,
                    std::string root_SessionID,
                    std::string parent_SessionID,

                    std::string OsVersion,
                    HANDLE pid,

                    std::string API_Json,

                    ULONG64 nano_timestamp
                );

                /*
                    ETW 이벤트
                */
                void Send_Log_ETW(
                    std::string SessionID,
                    std::string root_SessionID,
                    std::string parent_SessionID,

                    HANDLE pid,

                    std::string ProviderName,
                    std::string EventName,
                    unsigned long EventVersion,
                    unsigned long EventId,
                    unsigned long EventFlags,

                    std::string fieldsJson,

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