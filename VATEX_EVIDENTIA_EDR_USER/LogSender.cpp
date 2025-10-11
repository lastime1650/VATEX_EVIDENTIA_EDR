#include "LogSender.hpp"
#include <regex>
namespace EDR
{
    namespace LogSender
    {
        namespace Windows
        {

            std::string double_slash(const std::string& Str)
            {
                // 단일 '\'를 '\\'로 변환
                std::string sanitizedMessage;
                sanitizedMessage.reserve(Str.size()); // 성능 최적화

                for (char c : Str) {
                    if (c == '\\') {
                        sanitizedMessage += "\\\\";
                    }
                    else {
                        sanitizedMessage += c;
                    }
                }

                return sanitizedMessage;
            }

            bool IsValidByte(unsigned char c)
            {
                // 0x20 ~ 0x7E: ASCII printable
                // 0xA1 ~ 0xFE: CP949 한글 첫/둘 바이트 가능 범위 (간단 예시)
                if ((c >= 0x20 && c <= 0x7E) || (c >= 0xA1 && c <= 0xFE))
                    return true;
                return false;
            }

            std::string FilterValidBytes(const std::string& input)
            {
                std::string output;
                output.reserve(input.size());

                for (unsigned char c : input)
                {
                    if (IsValidByte(c))
                        output.push_back(c);
                }

                return output;
            }

            void LogSender::Send_Log_Process_Remove(

                std::string SessionID,
                std::string root_SessionID,
                std::string parent_SessionID,

                std::string OsVersion,

                HANDLE pid,

                ULONG64 nano_timestamp
            )
            {
                Kafka.InsertMessage(
                    fmt::format(
                        R"(
                            {{
                                "header": {{
                                    "agentid": "{}",
									"root_sessionid": "{}",
                                    "parent_sessionid": "{}",
								    "sessionid": "{}",
                                    "os": {{
                                        "version": "{}",
                                        "type": "{}"
                                    }},
                                    "pid": {},
                                    "nano_timestamp": {}
                                }},
                                "body": {{
                                    "process" : {{
                                        "action": "{}"
                                    }}
                                }}
                            }}
                    )", AgentID, root_SessionID, parent_SessionID, SessionID, OsVersion, "Windows", (ULONG64)pid, nano_timestamp,
                        "remove"
                    )
                );
            }
            void LogSender::Send_Log_Process_Create(

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
            )
            {
                

                Kafka.InsertMessage(
                    fmt::format(
                        R"(
                            {{
                                "header": {{
                                    "agentid": "{}",
                                    "root_sessionid": "{}",
                                    "parent_sessionid": "{}",
								    "sessionid": "{}",
                                    "os": {{
                                        "version": "{}",
                                        "type": "{}"
                                    }},
                                    "pid": {},
									"nano_timestamp": {}
                                }},
                                "body": {{

                                    "user": {{
		                                "sid": "{}",
                                        "username": "{}"
                                    }},

                                    "process" : {{
                                        "action": "{}",
                                        "exe_path": "{}",
                                        "exe_size": {},
                                        "exe_sha256": "{}",
                                        "commandline": "{}",

                                        "ppid" : {},
                                        "parent_exe_path": "{}",
                                        "parent_exe_size": {},
                                        "parent_exe_sha256": "{}"
                                    
                                    }}
                                }}
                            }}
                    )", AgentID, root_SessionID, parent_SessionID, SessionID, OsVersion, "Windows", (ULONG64)pid, nano_timestamp,
                        double_slash(SID), double_slash(Username),
                        "create", double_slash(self_exe_path), self_exe_file_size, self_exe_bin_sha256, std::regex_replace(double_slash(CommandLine), std::regex("\""), "\\\""),
                        (ULONG64)ppid, double_slash(parent_exe_path), parent_exe_file_size, parent_exe_bin_sha256
                    )
                );
            }
            void LogSender::Send_Log_Network(

                std::string SessionID,
                std::string root_SessionID,
                std::string parent_SessionID,

                std::string OsVersion,
                HANDLE pid,
                ULONG32 interface_index,
                std::string macSrc,
                std::string macDest,
                std::string ipSrc,
                ULONG32 portSrc,
                std::string ipDest,
                ULONG32 portDest,
                BOOLEAN is_INGRESS,
                ULONG32 packetSize,
                std::string protocol,
                ULONG64 nano_timestamp,

                std::string PacketSessionID,
                ULONG64 first_seen_nano_timestamp,
                ULONG64 last_seen_nano_timestamp
            )
            {
                Kafka.InsertMessage(
                    fmt::format(R"(
                        {{
                            "header": {{
                                "agentid": "{}",
								"root_sessionid": "{}",
                                "parent_sessionid": "{}",
								"sessionid": "{}",
                                "os": {{
                                    "version": "{}",
                                    "type": "{}"
                                }},
                                "pid": {},
                                "nano_timestamp": {}
                            }},
                            "body": {{
                                "network" : {{
                                    "interface_index": {}, 
                                    "protocol": "{}",
                                    "packetsize" : {},
                                    "sourcemac": "{}",
                                    "destinationmac": "{}",
                                    "sourceip": "{}",
                                    "sourceport": {},
                                    "destinationip": "{}",
                                    "destinationport": {},
                                    "direction": "{}",
                                    
                                    "session": {{
                                        "sessionid": "{}",
                                        "first_seen": {},
                                        "last_seen": {}
                                    }}
                                }}
                            }}
                            
                        }}
                    )", AgentID, root_SessionID, parent_SessionID, SessionID, OsVersion, "Windows", (ULONG64)pid, nano_timestamp,
                        interface_index, protocol, packetSize, macSrc, macDest, ipSrc, portSrc, ipDest, portDest, is_INGRESS ? "in" : "out",
                        PacketSessionID, first_seen_nano_timestamp, last_seen_nano_timestamp)
                );
            }

            void LogSender::Send_Log_FileSystem(
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
            )
            {
                Kafka.InsertMessage(
                    fmt::format(R"(
                        {{
                            "header": {{
                                "agentid": "{}",
								"root_sessionid": "{}",
                                "parent_sessionid": "{}",
								"sessionid": "{}",
                                "os": {{
                                    "version": "{}",
                                    "type": "{}"
                                }},
                                "pid": {},
                                "nano_timestamp": {}
                            }},
                            "body": {{
                                "filesystem" : {{
                                    "action": "{}",
                                    "filepath" : "{}",            
                                    "filesize": {},
                                    "filesha256": "{}"
                                }}
                            }}
                            
                        }}
                    )", AgentID, root_SessionID, parent_SessionID, SessionID, OsVersion, "Windows", (ULONG64)pid, nano_timestamp,
                        Action, double_slash(FilePath), filesize, FileSHA256)
                );
            }

            void LogSender::Send_Log_ImageLoad(

                std::string SessionID,
                std::string root_SessionID,
                std::string parent_SessionID,

                std::string OsVersion,
                HANDLE pid,
                std::string FilePath,
                ULONG64 filesize,
                std::string file_sha256,
                ULONG64 nano_timestamp
            )
            {
                Kafka.InsertMessage(
                    fmt::format(R"(
                        {{
                            "header": {{
                                "agentid": "{}",
								"root_sessionid": "{}",
                                "parent_sessionid": "{}",
								"sessionid": "{}",
                                "os": {{
                                    "version": "{}",
                                    "type": "{}"
                                }},
                                "pid": {},
                                "nano_timestamp": {}
                            }},
                            "body": {{
                                "imageload" : {{
                                    "filepath" : "{}",
                                    "filesize": {},
                                    "filesha256": "{}"
                                }}
                            }}
                            
                        }}
                    )", AgentID, root_SessionID, parent_SessionID, SessionID, OsVersion, "Windows", (ULONG64)pid, nano_timestamp,
                        double_slash(FilePath), filesize, file_sha256)
                );
            }

            void LogSender::Send_Log_ProcessAccess(

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
            )
            {

                std::vector<std::string> quoted;
                quoted.reserve(DesiredAccess.size());
                for (auto& s : DesiredAccess) {
                    quoted.push_back(fmt::format("\"{}\"", s));
                }
                std::string DesiredAccessJsonArrayString = fmt::format("[{}]", fmt::join(quoted, ", "));

                Kafka.InsertMessage(
                    fmt::format(R"(
                        {{
                            "header": {{
                                "agentid": "{}",
                                "root_sessionid": "{}",
                                "parent_sessionid": "{}",
								"sessionid": "{}",
                                "os": {{
                                    "version": "{}",
                                    "type": "{}"
                                }},
                                "pid": {},
                                "nano_timestamp": {}
                            }},
                            "body": {{
                                "processaccess" : {{
                                    "handletype" : "{}",
                                    "target_pid": {},
                                    "filepath": "{}",
									"desiredaccesses": {}
                                }}
                            }}
                            
                        }}
                    )", AgentID, root_SessionID, parent_SessionID, SessionID, OsVersion, "Windows", (ULONG64)pid, nano_timestamp,
                        CreateHandle, (ULONG64)Target_ProcessId, double_slash(TargetProcess_Path), DesiredAccessJsonArrayString)
                );
            }

            

            void LogSender::Send_Log_APICall(
                std::string SessionID,
                std::string root_SessionID,
                std::string parent_SessionID,

                std::string OsVersion,
                HANDLE pid,

                std::string API_Json,

                ULONG64 nano_timestamp
            )
            {

                
                Kafka.InsertMessage(
                    fmt::format(R"(
                        {{
                            "header": {{
                                "agentid": "{}",
								"root_sessionid": "{}",
                                "parent_sessionid": "{}",
								"sessionid": "{}",
                                "os": {{
                                    "version": "{}",
                                    "type": "{}"
                                }},
                                "pid": {},
                                "nano_timestamp": {}
                            }},
                            "body": {{
                                "apicall" : "{}"
                            }}
                            
                        }}
                    )", AgentID, root_SessionID, parent_SessionID, SessionID, OsVersion, "Windows", (ULONG64)pid, nano_timestamp,
                        API_Json)
                );
            }

            void LogSender::Send_Log_Registry(

                std::string SessionID,
                std::string root_SessionID,
                std::string parent_SessionID,

                std::string OsVersion,
                HANDLE pid,

                std::string RegistryKeyClass,
                std::string Target_Name,

                ULONG64 nano_timestamp
            )
            {
                Kafka.InsertMessage(
                    fmt::format(R"(
                        {{
                            "header": {{
                                "agentid": "{}",
								"root_sessionid": "{}",
                                "parent_sessionid": "{}",
								"sessionid": "{}",
                                "os": {{
                                    "version": "{}",
                                    "type": "{}"
                                }},
                                "pid": {},
                                "nano_timestamp": {}
                            }},
                            "body": {{
                                "registry" : {{
                                    "keyclass" : "{}",
                                    "name": "{}"
                                }}
                            }}
                            
                        }}
                    )", AgentID, root_SessionID, parent_SessionID, SessionID, OsVersion, "Windows", (ULONG64)pid, nano_timestamp,
                        double_slash(RegistryKeyClass), double_slash(FilterValidBytes(Target_Name)))
                );
                /*
                   ["body"]["reigstry"]["keyclass"] 에는 무슨 std::string값으로 오는가?
                   
                   실제 다음과 같은 enum값 이름으로 온다.
                   typedef enum _REG_NOTIFY_CLASS {
    RegNtDeleteKey,
    RegNtPreDeleteKey = RegNtDeleteKey,
    RegNtSetValueKey,
    RegNtPreSetValueKey = RegNtSetValueKey,
    RegNtDeleteValueKey,
    RegNtPreDeleteValueKey = RegNtDeleteValueKey,
    RegNtSetInformationKey,
    RegNtPreSetInformationKey = RegNtSetInformationKey,
    RegNtRenameKey,
    RegNtPreRenameKey = RegNtRenameKey,
    RegNtEnumerateKey,
    RegNtPreEnumerateKey = RegNtEnumerateKey,
    RegNtEnumerateValueKey,
    RegNtPreEnumerateValueKey = RegNtEnumerateValueKey,
    RegNtQueryKey,
    RegNtPreQueryKey = RegNtQueryKey,
    RegNtQueryValueKey,
    RegNtPreQueryValueKey = RegNtQueryValueKey,
    RegNtQueryMultipleValueKey,
    RegNtPreQueryMultipleValueKey = RegNtQueryMultipleValueKey,
    RegNtPreCreateKey,
    RegNtPostCreateKey,
    RegNtPreOpenKey,
    RegNtPostOpenKey,
    RegNtKeyHandleClose,
    RegNtPreKeyHandleClose = RegNtKeyHandleClose,
    //
    // .Net only
    //
    RegNtPostDeleteKey,
    RegNtPostSetValueKey,
    RegNtPostDeleteValueKey,
    RegNtPostSetInformationKey,
    RegNtPostRenameKey,
    RegNtPostEnumerateKey,
    RegNtPostEnumerateValueKey,
    RegNtPostQueryKey,
    RegNtPostQueryValueKey,
    RegNtPostQueryMultipleValueKey,
    RegNtPostKeyHandleClose,
    RegNtPreCreateKeyEx,
    RegNtPostCreateKeyEx,
    RegNtPreOpenKeyEx,
    RegNtPostOpenKeyEx,
    //
    // new to Windows Vista
    //
    RegNtPreFlushKey,
    RegNtPostFlushKey,
    RegNtPreLoadKey,
    RegNtPostLoadKey,
    RegNtPreUnLoadKey,
    RegNtPostUnLoadKey,
    RegNtPreQueryKeySecurity,
    RegNtPostQueryKeySecurity,
    RegNtPreSetKeySecurity,
    RegNtPostSetKeySecurity,
    //
    // per-object context cleanup
    //
    RegNtCallbackObjectContextCleanup,
    //
    // new in Vista SP2
    //
    RegNtPreRestoreKey,
    RegNtPostRestoreKey,
    RegNtPreSaveKey,
    RegNtPostSaveKey,
    RegNtPreReplaceKey,
    RegNtPostReplaceKey,
    //
    // new to Windows 10
    //
    RegNtPreQueryKeyName,
    RegNtPostQueryKeyName,
    RegNtPreSaveMergedKey,
    RegNtPostSaveMergedKey,

    MaxRegNtNotifyClass //should always be the last enum
} REG_NOTIFY_CLASS;

                */
            }

            void LogSender::Send_Log_Registry(

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
            )
            {
                Kafka.InsertMessage(
                    fmt::format(R"(
                        {{
                            "header": {{
                                "agentid": "{}",
								"root_sessionid": "{}",
                                "parent_sessionid": "{}",
								"sessionid": "{}",
                                "os": {{
                                    "version": "{}",
                                    "type": "{}"
                                }},
                                "pid": {},
                                "nano_timestamp": {}
                            }},
                            "body": {{
                                "registry" : {{
                                    "keyclass" : "{}",
                                    "name": "{}",
                                    "newold" : {{
                                        "oldname": "{}",
                                        "newname": "{}"
                                    }}
                                }}
                            }}
                            
                        }}
                    )", AgentID, root_SessionID, parent_SessionID, SessionID, OsVersion, "Windows", (ULONG64)pid, nano_timestamp,
                        RegistryKeyClass, double_slash(Target_Name), double_slash(OldName), double_slash(NewName) )
                );
            }

        }
    }
}
