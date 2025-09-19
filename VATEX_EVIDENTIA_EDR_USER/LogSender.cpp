#include "LogSender.hpp"

namespace EDR
{
    namespace LogSender
    {
        namespace Windows
        {
            void LogSender::Send_Log_Process_Remove(

                std::string SessionID,

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
                    )", AgentID, SessionID, OsVersion, "Windows", pid, nano_timestamp,
                        "remove"
                    )
                );
            }
            void LogSender::Send_Log_Process_Create(

                std::string SessionID,

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
                    )", AgentID, SessionID, OsVersion, "Windows", pid, nano_timestamp,
						"create", self_exe_path, self_exe_file_size, self_exe_bin_sha256, CommandLine,
						ppid, parent_exe_path, parent_exe_file_size, parent_exe_bin_sha256
                    )
                );
            }
            void LogSender::Send_Log_Network(

                std::string SessionID,

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
            )
            {
                Kafka.InsertMessage(
                    fmt::format(R"(
                        {{
                            "header": {{
                                "agentid": "{}",
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
                                    "interface_name": "{}", 
                                    "protocol": "{}",
                                    "packetsize" : {},
                                    "sourceip": "{}",
                                    "sourceport": {},
                                    "destinationip": "{}",
                                    "destinationport": {},
                                    "direction": "{}"
                                }}
                            }}
                            
                        }}
                    )", AgentID, SessionID, OsVersion, "Windows", pid, nano_timestamp,
                        interface_name, protocol, packetSize, ipSrc, portSrc, ipDest, portDest, is_INGRESS ? "in" : "out")
                );
            }

            void LogSender::Send_Log_FileSystem(
                std::string SessionID,

                std::string OsVersion,
                HANDLE pid,
                std::string Action,
                std::string FilePath,
                ULONG32 filesize,
                ULONG64 nano_timestamp
            )
            {
                Kafka.InsertMessage(
                    fmt::format(R"(
                        {{
                            "header": {{
                                "agentid": "{}",
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
                                    "filesize": {}
                                }}
                            }}
                            
                        }}
                    )", AgentID, SessionID, OsVersion, "Windows", pid, nano_timestamp,
                        Action, FilePath, filesize)
                );
            }

            void LogSender::Send_Log_ImageLoad(

                std::string SessionID,

                std::string OsVersion,
                HANDLE pid,
                std::string FilePath,
                ULONG32 filesize,
                std::string file_sha256,
                ULONG64 nano_timestamp
            )
            {
                Kafka.InsertMessage(
                    fmt::format(R"(
                        {{
                            "header": {{
                                "agentid": "{}",
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
                    )", AgentID, SessionID, OsVersion, "Windows", pid, nano_timestamp,
                        FilePath, filesize, file_sha256)
                );
            }

            void LogSender::Send_Log_ProcessAccess(

                std::string SessionID,

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
                    )", AgentID, SessionID, OsVersion, "Windows", pid, nano_timestamp,
                        CreateHandle, Target_ProcessId, TargetProcess_Path, DesiredAccessJsonArrayString)
                );
            }

        }
    }
}
