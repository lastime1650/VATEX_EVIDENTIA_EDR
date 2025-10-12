#include "LogReceiver.hpp"
#include "APC.hpp"

std::string ProtocolToString(int protocol);

#include <iostream>
namespace EDR
{
	namespace LogReceiver
	{

		bool LogManager::Run(std::string EDR_TCP_SERVER_IP, unsigned int EDR_TCP_SERVER_PORT)
		{
			if (is_threading) // 최초 1번 실행
				return false; 

			bool status = false;

			

			// 1. IOCTL 연결
			if (!ioctl.INITIALIZE(
				(HANDLE)GetCurrentProcessId()
			))
				return false;

			is_threading = true;

			// 2. IOCTL 데이터 요청 후 수신 스레드
			RecieveLogDataThread = std::thread(
				[this, test = &ioctl, is_threading = &is_threading, queue = &this->Queue]()
				{
					while (*is_threading)
					{
						PVOID out_UserAllocatedFileBinaryAddress = NULL;
						ULONG64 out_BinarySize = 0;
						ioctl.REQUEST_LOG(
							(PVOID*)&out_UserAllocatedFileBinaryAddress,
							&out_BinarySize
						);

						std::cout << "Log Received Size: " << out_BinarySize << std::endl;

						for (ULONG64 i = 0; i < out_BinarySize; i += sizeof(PVOID))
						{
							/*
								Kernel - User [ 로그 전송 ]
								
								PVOID(x64기준 8바이트)씩 나눠서 사전에 커널에서 유저모드에 할당한 공간에 로그 주소를 저장함

							*/
							PVOID log = *(PVOID*)((PUCHAR)out_UserAllocatedFileBinaryAddress + i);

							EDR::EventLog::Struct::EventLog_Header* header = (EDR::EventLog::Struct::EventLog_Header*)log;

							ULONG64 LogSize = 0;
							switch (header->Type)
							{
								case EDR::EventLog::Enum::Process_Create:
								{
									LogSize = sizeof(EDR::EventLog::Struct::Process::EventLog_Process_Create);
									break;
								}
								case EDR::EventLog::Enum::Process_Terminate:
								{
									LogSize = sizeof(EDR::EventLog::Struct::Process::EventLog_Process_Terminate);
									break;
								}
								case EDR::EventLog::Enum::ImageLoad:
								{
									LogSize = sizeof(EDR::EventLog::Struct::ImageLoad::EventLog_ImageLoad);
									break;
								}
								case EDR::EventLog::Enum::Network:
								{
									LogSize = sizeof(EDR::EventLog::Struct::Network::EventLog_Process_Network);
									break;
								}
								case EDR::EventLog::Enum::Filesystem:
								{
									LogSize = sizeof(EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem);
									break;
								}
								case EDR::EventLog::Enum::ObRegisterCallback:
								{
									LogSize = sizeof(EDR::EventLog::Struct::ObRegisterCallback::EventLog_Process_ObRegisterCallback);
									break;
								}
								case EDR::EventLog::Enum::Registry_CompleteNameLog:
								{
									LogSize = sizeof(EDR::EventLog::Struct::Registry::EventLog_Process_Registry_CompleteorObjectNameLog);
									break;
								}
								case EDR::EventLog::Enum::Registry_OldNewLog:
								{
									LogSize = sizeof(EDR::EventLog::Struct::Registry::EventLog_Process_Registry_OldNewNameLog);
									break;
								}
								case EDR::EventLog::Enum::apicall:
								{
									LogSize = sizeof(EDR::EventLog::Struct::ApiCall::EventLog_ApiCall);
									break;
								}
								default:
								{
									std::cout << "이해할 수 없는 로그" << std::endl;
									break;
								}

							}


							if (LogSize)
							{
								log_s logStruct;
								logStruct.Type = header->Type;
								logStruct.logData = new unsigned char[LogSize];
								memcpy(logStruct.logData, log, LogSize);
								logStruct.logSize = LogSize;

								queue->put(logStruct); // 큐로 데이터 전송
							}
							

							VirtualFree(log, 0, MEM_RELEASE);
						}

						VirtualFree(out_UserAllocatedFileBinaryAddress, 0, MEM_RELEASE);

						Sleep(1000);
					}
				}
			);
			RecieveLogDataThread.detach();
			
			// 3. 로그 처리 스레드
			RecieveQueueThread = std::thread(
				[this, test = &ioctl, is_threading = &is_threading, queue = &this->Queue]()
				{
					while (*is_threading)
					{
						auto Log = queue->get();
						
						
						switch (Log.Type)
						{
						case EDR::EventLog::Enum::Process_Create:
						{
							EDR::EventLog::Struct::Process::EventLog_Process_Create* ProcessCreatedLog = reinterpret_cast<EDR::EventLog::Struct::Process::EventLog_Process_Create*>(Log.logData);

							


							std::string root_SessionID;
							std::string SessionID;
							std::string parent_SessionID;
							
							

							
							ProcessSessionManager.ProcessCreate(
								ProcessCreatedLog->header.ProcessId,
								ProcessCreatedLog->body.Parent_ProcessId,
								SessionID,
								root_SessionID,
								parent_SessionID
							);
							if (SessionID.empty())
								break;

							// logSend

							std::string Username;
							EDR::Util::Windows::SID_to_Username(
								ProcessCreatedLog->body.post.SID,
								Username
							);

							WindowsLogSender.Send_Log_Process_Create(
								SessionID,
								root_SessionID,
								parent_SessionID,

								ProcessCreatedLog->body.post.SID,
								Username,
								ProcessCreatedLog->header.Version,

								ProcessCreatedLog->header.ProcessId,

								ProcessCreatedLog->body.post.Self_Process_exe_path,
								ProcessCreatedLog->body.post.Self_Process_exe_size,
								ProcessCreatedLog->body.post.Self_Process_exe_SHA256,

								ProcessCreatedLog->body.Parent_ProcessId,
								ProcessCreatedLog->body.post.Parent_Process_exe_path,
								ProcessCreatedLog->body.post.Parent_Process_exe_size,
								ProcessCreatedLog->body.post.Parent_Process_exe_SHA256,

								ProcessCreatedLog->body.CommandLine,

								ProcessCreatedLog->header.NanoTimestamp
							);

							break;
						}
						
						case EDR::EventLog::Enum::Process_Terminate:
						{
							EDR::EventLog::Struct::Process::EventLog_Process_Terminate* ProcessTerminateLog = reinterpret_cast<EDR::EventLog::Struct::Process::EventLog_Process_Terminate*>(Log.logData);

							std::string root_SessionID;
							std::string SessionID;
							std::string parent_SessionID;

							ProcessSessionManager.ProcessRemove(
								ProcessTerminateLog->header.ProcessId,
								SessionID,
								root_SessionID,
								parent_SessionID
							);
							if (SessionID.empty())
								break;

							// logSend
							WindowsLogSender.Send_Log_Process_Remove(
								SessionID,
								root_SessionID,
								parent_SessionID,

								ProcessTerminateLog->header.Version,
								ProcessTerminateLog->header.ProcessId,
								ProcessTerminateLog->header.NanoTimestamp
							);

							break;
						}
						case EDR::EventLog::Enum::ImageLoad:
						{
							EDR::EventLog::Struct::ImageLoad::EventLog_ImageLoad* ImageLoadLog = reinterpret_cast<EDR::EventLog::Struct::ImageLoad::EventLog_ImageLoad*>(Log.logData);

							std::string root_SessionID;
							std::string SessionID;
							std::string parent_SessionID;

							ProcessSessionManager.AppendingEvent(
								ImageLoadLog->header.ProcessId,
								SessionID,
								root_SessionID,
								parent_SessionID
							);
							if (SessionID.empty())
								break;

							// logSend
							WindowsLogSender.Send_Log_ImageLoad(
								SessionID,
								root_SessionID,
								parent_SessionID,

								ImageLoadLog->header.Version,
								ImageLoadLog->header.ProcessId,

								ImageLoadLog->body.ImagePathAnsi,
								ImageLoadLog->body.post.Parent_Process_exe_size,
								ImageLoadLog->body.post.Parent_Process_exe_SHA256,

								ImageLoadLog->header.NanoTimestamp
							);

							break;
						}
						case EDR::EventLog::Enum::Network:
						{
							EDR::EventLog::Struct::Network::EventLog_Process_Network* NetworkLog = reinterpret_cast<EDR::EventLog::Struct::Network::EventLog_Process_Network*>(Log.logData);

							std::string root_SessionID;
							std::string SessionID;
							std::string parent_SessionID;

							// [ 프로세스 세션 ]
							ProcessSessionManager.AppendingEvent(
								NetworkLog->header.ProcessId,
								SessionID,
								root_SessionID,
								parent_SessionID
							);
							if (SessionID.empty())
								break;

							// [ 네트워크 세션 ]
							EDR::Session::Network::NetworkSessionInfo Network_SessionINFO;
							NetworkSessionManager.Get_NetworkSessionInfo(
								NetworkLog->body.ProtocolNumber,
								NetworkLog->body.LOCAL_IP,
								NetworkLog->body.LOCAL_PORT,
								NetworkLog->body.REMOTE_IP,
								NetworkLog->body.REMOTE_PORT,

								Network_SessionINFO
							);
							Network_SessionINFO.SessionID;
							Network_SessionINFO.first_seen_nanotimestamp;
							Network_SessionINFO.last_seen_nanotimestamp;

							//std::cout << NetworkLog->body.ProtocolNumber << " || " << (NetworkLog->body.is_INBOUND ? "In" : "out") << " || " << NetworkLog->body.PacketSize << "PacketNetworkSessionID:" << Network_SessionINFO.SessionID << std::endl;

							// logSend
							WindowsLogSender.Send_Log_Network(
								SessionID,
								root_SessionID,
								parent_SessionID,

								NetworkLog->header.Version,
								NetworkLog->header.ProcessId,

								NetworkLog->body.ifindex,
								NetworkLog->body.SourceMacAddress,
								NetworkLog->body.DestinationMacAddress,
								NetworkLog->body.LOCAL_IP,
								NetworkLog->body.LOCAL_PORT,
								NetworkLog->body.REMOTE_IP,
								NetworkLog->body.REMOTE_PORT,
								NetworkLog->body.is_INBOUND,
								NetworkLog->body.PacketSize,
								ProtocolToString(NetworkLog->body.ProtocolNumber),

								NetworkLog->header.NanoTimestamp,

								Network_SessionINFO.SessionID,
								Network_SessionINFO.first_seen_nanotimestamp,
								Network_SessionINFO.last_seen_nanotimestamp
							);

							break;
						}
						case EDR::EventLog::Enum::Filesystem:
						{
							EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem* FileSystemLog = reinterpret_cast<EDR::EventLog::Struct::FileSystem::EventLog_Process_Filesystem*>(Log.logData);

							std::string root_SessionID;
							std::string SessionID;
							std::string parent_SessionID;

							ProcessSessionManager.AppendingEvent(
								FileSystemLog->header.ProcessId,
								SessionID,
								root_SessionID,
								parent_SessionID
							);
							if (SessionID.empty())
								break;

							std::string FileAction;
							switch (FileSystemLog->body.Action)
							{
							case EDR::EventLog::Enum::FileSystem::open:
								FileAction = "open";
								break;
							case EDR::EventLog::Enum::FileSystem::create:
								FileAction = "create";
								break;
							case EDR::EventLog::Enum::FileSystem::overwritten:
								FileAction = "overwritten";
								break;
							case EDR::EventLog::Enum::FileSystem::superseded:
								FileAction = "superseded";
								break;
							case EDR::EventLog::Enum::FileSystem::exists:
								FileAction = "exists";
								break;
							case EDR::EventLog::Enum::FileSystem::write:
								FileAction = "write";
								break;
							case EDR::EventLog::Enum::FileSystem::read:
								FileAction = "read";
								break;
							case EDR::EventLog::Enum::FileSystem::remove:
								FileAction = "remove";
								break;
							case EDR::EventLog::Enum::FileSystem::rename:
								FileAction = "rename";
								break;
							default:
							{
								std::cout << "알 수 없는 파일 액션";
							}
							}

							// LogSend
							WindowsLogSender.Send_Log_FileSystem(
								SessionID,
								root_SessionID,
								parent_SessionID,

								FileSystemLog->header.Version,
								FileSystemLog->header.ProcessId,

								FileAction,
								FileSystemLog->body.FilePath,
								FileSystemLog->body.sha256.SHA256,
								FileSystemLog->body.post.FileSize,

								FileSystemLog->header.NanoTimestamp
							);

							break;
						}
						case EDR::EventLog::Enum::ObRegisterCallback:
						{
							EDR::EventLog::Struct::ObRegisterCallback::EventLog_Process_ObRegisterCallback* ObRegisterCallbackLog = reinterpret_cast<EDR::EventLog::Struct::ObRegisterCallback::EventLog_Process_ObRegisterCallback*>(Log.logData);

							std::string root_SessionID;
							std::string SessionID;
							std::string parent_SessionID;

							ProcessSessionManager.AppendingEvent(
								ObRegisterCallbackLog->header.ProcessId,
								SessionID,
								root_SessionID,
								parent_SessionID
							);
							if (SessionID.empty())
								break;

							std::vector<std::string> DesiredAccessVec;
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_ALL_ACCESS)
								DesiredAccessVec.push_back("PROCESS_ALL_ACCESS");


#define PROCESS_SYNCHRONIZE                0x00100000
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_CREATE_PROCESS)
								DesiredAccessVec.push_back("PROCESS_CREATE_PROCESS");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_CREATE_THREAD)
								DesiredAccessVec.push_back("PROCESS_CREATE_THREAD");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_DUP_HANDLE)
								DesiredAccessVec.push_back("PROCESS_DUP_HANDLE");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_QUERY_INFORMATION)
								DesiredAccessVec.push_back("PROCESS_QUERY_INFORMATION");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_QUERY_LIMITED_INFORMATION)
								DesiredAccessVec.push_back("PROCESS_QUERY_LIMITED_INFORMATION");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_SET_INFORMATION)
								DesiredAccessVec.push_back("PROCESS_SET_INFORMATION");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_SET_QUOTA)
								DesiredAccessVec.push_back("PROCESS_SET_QUOTA");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_SUSPEND_RESUME)
								DesiredAccessVec.push_back("PROCESS_SUSPEND_RESUME");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_TERMINATE)
								DesiredAccessVec.push_back("PROCESS_TERMINATE");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_VM_OPERATION)
								DesiredAccessVec.push_back("PROCESS_VM_OPERATION");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_VM_READ)
								DesiredAccessVec.push_back("PROCESS_VM_READ");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_VM_WRITE)
								DesiredAccessVec.push_back("PROCESS_VM_WRITE");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_SET_LIMITED_INFORMATION)
								DesiredAccessVec.push_back("PROCESS_SET_LIMITED_INFORMATION");
							if (ObRegisterCallbackLog->body.DesiredAccess & PROCESS_SYNCHRONIZE)
								DesiredAccessVec.push_back("PROCESS_SYNCHRONIZE");

							// 표준 권한
							if (ObRegisterCallbackLog->body.DesiredAccess & DELETE)
								DesiredAccessVec.push_back("DELETE");
							if (ObRegisterCallbackLog->body.DesiredAccess & READ_CONTROL)
								DesiredAccessVec.push_back("READ_CONTROL");
							if (ObRegisterCallbackLog->body.DesiredAccess & WRITE_DAC)
								DesiredAccessVec.push_back("WRITE_DAC");
							if (ObRegisterCallbackLog->body.DesiredAccess & WRITE_OWNER)
								DesiredAccessVec.push_back("WRITE_OWNER");

							// Generic
							if (ObRegisterCallbackLog->body.DesiredAccess & GENERIC_READ)
								DesiredAccessVec.push_back("GENERIC_READ");
							if (ObRegisterCallbackLog->body.DesiredAccess & GENERIC_WRITE)
								DesiredAccessVec.push_back("GENERIC_WRITE");
							if (ObRegisterCallbackLog->body.DesiredAccess & GENERIC_EXECUTE)
								DesiredAccessVec.push_back("GENERIC_EXECUTE");
							if (ObRegisterCallbackLog->body.DesiredAccess & GENERIC_ALL)
								DesiredAccessVec.push_back("GENERIC_ALL");


							WindowsLogSender.Send_Log_ProcessAccess(
								SessionID,
								root_SessionID,
								parent_SessionID,

								ObRegisterCallbackLog->header.Version,
								ObRegisterCallbackLog->header.ProcessId,

								ObRegisterCallbackLog->body.is_CreateHandleInformation ? "create" : "duplicate",
								ObRegisterCallbackLog->body.Target_ProcessId,
								ObRegisterCallbackLog->body.TargetProcess_Path,
								DesiredAccessVec,

								ObRegisterCallbackLog->header.NanoTimestamp
							);

							break;

						}

						case EDR::EventLog::Enum::Registry_CompleteNameLog:
						{
							EDR::EventLog::Struct::Registry::EventLog_Process_Registry_CompleteorObjectNameLog* RegistryCompleteNameLog = reinterpret_cast<EDR::EventLog::Struct::Registry::EventLog_Process_Registry_CompleteorObjectNameLog*>(Log.logData);

							std::string root_SessionID;
							std::string SessionID;
							std::string parent_SessionID;

							ProcessSessionManager.AppendingEvent(
								RegistryCompleteNameLog->header.ProcessId,
								SessionID,
								root_SessionID,
								parent_SessionID
							);
							if (SessionID.empty())
								break;
							//std::cout << "[Registry_CompleteNameLog] class: " << RegistryCompleteNameLog->body.FunctionName << " Name: " << RegistryCompleteNameLog->body.Name << std::endl;
							WindowsLogSender.Send_Log_Registry(
								SessionID,
								root_SessionID,
								parent_SessionID,

								RegistryCompleteNameLog->header.Version,
								RegistryCompleteNameLog->header.ProcessId,

								RegistryCompleteNameLog->body.FunctionName,
								RegistryCompleteNameLog->body.Name,

								RegistryCompleteNameLog->header.NanoTimestamp
							);

							break;
						}
						case EDR::EventLog::Enum::Registry_OldNewLog:
						{
							EDR::EventLog::Struct::Registry::EventLog_Process_Registry_OldNewNameLog* RegistryOldNewNameLog = reinterpret_cast<EDR::EventLog::Struct::Registry::EventLog_Process_Registry_OldNewNameLog*>(Log.logData);

							std::string root_SessionID;
							std::string SessionID;
							std::string parent_SessionID;

							ProcessSessionManager.AppendingEvent(
								RegistryOldNewNameLog->header.ProcessId,
								SessionID,
								root_SessionID,
								parent_SessionID
							);
							if (SessionID.empty())
								break;

							WindowsLogSender.Send_Log_Registry(
								SessionID,
								root_SessionID,
								parent_SessionID,

								RegistryOldNewNameLog->header.Version,
								RegistryOldNewNameLog->header.ProcessId,

								RegistryOldNewNameLog->body.FunctionName,
								RegistryOldNewNameLog->body.Name,
								RegistryOldNewNameLog->body.OldName,
								RegistryOldNewNameLog->body.NewName,

								RegistryOldNewNameLog->header.NanoTimestamp
							);
							break;
						}
						case EDR::EventLog::Enum::apicall:
						{
							EDR::EventLog::Struct::ApiCall::EventLog_ApiCall* ApiCallLog = reinterpret_cast<EDR::EventLog::Struct::ApiCall::EventLog_ApiCall*>(Log.logData);

							std::string root_SessionID;
							std::string SessionID;
							std::string parent_SessionID;
							std::cout << "[ApiCall] Json: " << ApiCallLog->body.Json << std::endl;
							ProcessSessionManager.AppendingEvent(
								ApiCallLog->header.ProcessId,
								SessionID,
								root_SessionID,
								parent_SessionID
							);
							if (SessionID.empty())
								break;

							WindowsLogSender.Send_Log_APICall(
								SessionID,
								root_SessionID,
								parent_SessionID,

								ApiCallLog->header.Version,
								ApiCallLog->header.ProcessId,

								ApiCallLog->body.Json,

								ApiCallLog->header.NanoTimestamp
							);

							break;
						}
						default:
						{
							//std::cout << "이해할 수 없는 로그" << std::endl;
							break;
						}
						}
						
						delete[] Log.logData;
					}

					Sleep(2111);
					// queue clean
					while (queue->empty() == false)
					{
						auto Log = queue->get();
						delete[] Log.logData;
					}
					return;
				}
			);
			RecieveQueueThread.detach();

			// FIn. EDR 간 TCP 통신
			EDR_TCP.Run(EDR_TCP_SERVER_IP, EDR_TCP_SERVER_PORT);

			return status;
		}


	}

}

std::string ProtocolToString(int protocol) {
	switch (protocol) {
	case 0:   return "hopopt";
	case 1:   return "icmp";
	case 2:   return "igmp";
	case 3:   return "ggp";
	case 4:   return "ipv4";
	case 5:   return "st";
	case 6:   return "tcp";
	case 7:   return "cbt";
	case 8:   return "egp";
	case 9:   return "igp";
	case 10:  return "bbn-rcc-mon";
	case 11:  return "nvp-ii";
	case 12:  return "pup";
	case 13:  return "argus";
	case 14:  return "emcon";
	case 15:  return "xnet";
	case 16:  return "chaos";
	case 17:  return "udp";
	case 18:  return "mux";
	case 19:  return "dcn-meas";
	case 20:  return "hmp";
	case 21:  return "prm";
	case 22:  return "xns-idp";
	case 23:  return "trunk-1";
	case 24:  return "trunk-2";
	case 25:  return "leaf-1";
	case 26:  return "leaf-2";
	case 27:  return "rdp";
	case 28:  return "irtp";
	case 29:  return "iso-tp4";
	case 30:  return "netblt";
	case 31:  return "mfe-nsp";
	case 32:  return "merit-inp";
	case 33:  return "dccp";
	case 34:  return "3pc";
	case 35:  return "idpr";
	case 36:  return "xtp";
	case 37:  return "ddp";
	case 38:  return "idpr-cmtp";
	case 39:  return "tp++";
	case 40:  return "il";
	case 41:  return "ipv6";
	case 42:  return "sdrp";
	case 43:  return "ipv6-route";
	case 44:  return "ipv6-frag";
	case 45:  return "idrp";
	case 46:  return "rsvp";
	case 47:  return "gre";
	case 48:  return "dsn";
	case 49:  return "iatp";
	case 50:  return "stp";
	case 51:  return "srp";
	case 52:  return "uti";
	case 53:  return "swipe";
	case 54:  return "narp";
	case 55:  return "mobile";
	case 56:  return "ipv6";
	case 57:  return "cftp";
	case 58:  return "cal";
	case 59:  return "mtp";
	case 60:  return "ax.25";
	case 61:  return "os";
	case 62:  return "micp";
	case 63:  return "scc-sp";
	case 64:  return "etherip";
	case 65:  return "encap";
	case 66:  return "private";
	case 67:  return "gmtp";
	case 68:  return "ifmp";
	case 69:  return "pnni";
	case 70:  return "pim";
	case 71:  return "aris";
	case 72:  return "scps";
	case 73:  return "qnx";
	case 74:  return "a/n";
	case 75:  return "ipcomp";
	case 76:  return "snp";
	case 77:  return "compaq-peer";
	case 78:  return "ipx-in-ip";
	case 79:  return "vrrp";
	case 80:  return "pgm";
	case 81:  return "any";
	case 82:  return "l2tp";
	case 83:  return "ddx";
	case 84:  return "iatp";
	case 85:  return "stp";
	case 86:  return "srp";
	case 87:  return "uti";
	case 88:  return "swipe";
	case 89:  return "narp";
	case 90:  return "mobile";
	case 91:  return "ipv6";
	case 92:  return "cftp";
	case 93:  return "cal";
	case 94:  return "mtp";
	case 95:  return "ax.25";
	case 96:  return "os";
	case 97:  return "micp";
	case 98:  return "scc-sp";
	case 99:  return "etherip";
	case 100: return "encap";
	case 101: return "private";
	case 102: return "gmtp";
	case 103: return "ifmp";
	case 104: return "pnni";
	case 105: return "pim";
	case 106: return "aris";
	case 107: return "scps";
	case 108: return "qnx";
	case 109: return "a/n";
	case 110: return "ipcomp";
	case 111: return "snp";
	case 112: return "compaq-peer";
	case 113: return "ipx-in-ip";
	case 114: return "vrrp";
	case 115: return "pgm";
	case 116: return "any";
	case 117: return "l2tp";
	case 118: return "ddx";
	case 119: return "iatp";
	case 255: return "reserved";
	default:  return "unknown";
	}
}