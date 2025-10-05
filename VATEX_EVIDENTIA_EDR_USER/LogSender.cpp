#include "LogSender.hpp"

namespace EDR
{
    namespace LogSender
    {
        namespace Windows
        {
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
                                    "user": {{
		                                "sid": "{}",
                                        "username": "{}"
                                    }},
                                    "pid": {},
									"nano_timestamp": {}
                                }},
                                "body": {{
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
						"create", self_exe_path, self_exe_file_size, self_exe_bin_sha256, CommandLine,
                        (ULONG64)ppid, parent_exe_path, parent_exe_file_size, parent_exe_bin_sha256
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
                        interface_index, protocol, packetSize, ipSrc, portSrc, ipDest, portDest, is_INGRESS ? "in" : "out",
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
                        Action, FilePath, filesize, FileSHA256)
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
                        FilePath, filesize, file_sha256)
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
                        CreateHandle, (ULONG64)Target_ProcessId, TargetProcess_Path, DesiredAccessJsonArrayString)
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
                        RegistryKeyClass, Target_Name)
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
                        RegistryKeyClass, Target_Name, OldName, NewName)
                );
            }

        }
    }
}
