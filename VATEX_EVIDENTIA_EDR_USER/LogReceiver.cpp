#include "LogReceiver.hpp"
#include "APC.hpp"

std::string ProtocolToString(int protocol);
std::string PwchToString(PWCH pwch);


#include <iostream>
#include <variant>
namespace EDR
{
	namespace LogReceiver
	{

		auto escape_json = [](const std::string& s) {
			std::string out;
			out.reserve(s.size());
			for (char c : s) {
				switch (c) {
				case '\\': out += "\\\\"; break;
				case '"':  out += "\\\""; break;
				case '\n': out += "\\n"; break;
				case '\r': out += "\\r"; break;
				case '\t': out += "\\t"; break;
				default:   out += c; break;
				}
			}
			return out;
			};

		bool LogManager::Run(std::string EDR_TCP_SERVER_IP, unsigned int EDR_TCP_SERVER_PORT)
		{
			if (is_threading) // 최초 1번 실행
				return false; 

			bool status = false;

			// 1. IOCTL 연결
			if (!ioctl.INITIALIZE(
				(HANDLE)GetCurrentProcessId(),
				OS_VERSION
			))
				return false;

			is_threading = true;
			/*
			
				!!!!!!!!!!!!!!!! [ ONLY-KERNEL ] !!!!!!!!!!!!!!!!!!!!
			*/
			// 2. IOCTL 데이터 요청 후 수신 스레드
			for (int i = 0; i < parallel_Kernel_RecieveQueueThread_Count; i++)
			{
				EDR::EventLog::Enum::QueueTypes MyQueueType_ = (EDR::EventLog::Enum::QueueTypes)i;

				parallel_RecieveLogDataThread.push_back(
					std::move(
						std::thread(
							[this, test = &ioctl, MyQueueType = MyQueueType_, is_threading = &is_threading, queue = this->parallel_RecieveQueues[i] ]()
							{
								std::cout << "MyQueueType: " << MyQueueType << " Loaded " << std::endl;
								while (*is_threading)
								{
									try
									{
										PVOID out_UserAllocatedFileBinaryAddress = NULL;
										ULONG64 out_BinarySize = 0;
										ioctl.REQUEST_LOG(
											MyQueueType,
											(PVOID*)&out_UserAllocatedFileBinaryAddress,
											&out_BinarySize
										);
										
										if (!out_BinarySize)
										{
											Sleep(10);
											continue;
										}
										//if (MyQueueType == EDR::EventLog::Enum::QueueTypes::Queue_WFP)
											//std::cout << "Log Received Size: " << out_BinarySize << std::endl;

										SIZE_T MaxSize = out_BinarySize;
										PUCHAR StartAddress = (PUCHAR)out_UserAllocatedFileBinaryAddress;


										log_s logStruct;
										logStruct.LogDataType = EDR::EventLog::Enum::LengthBased;
										logStruct.Type = (EDR::EventLog::Enum::EventLog_Enum)0; // 사용X (data안에 식별할 수 있는 Enum존재) - Kernel 한정
										logStruct.logData = StartAddress;// new unsigned char[MaxSize];
										//memcpy(logStruct.logData, StartAddress, MaxSize);
										logStruct.logSize = MaxSize;
										
										queue->put(logStruct);

										//DebugBreak();
										//VirtualFree(StartAddress, 0, MEM_RELEASE);

										continue;
									}
									catch (const std::exception&)
									{
										std::cout << "[ERROR] KernelDataReceive Thread" << std::endl;
										continue;
									}

								}
							}
						)
					)
				);
				parallel_RecieveLogDataThread[i].detach();
			}

			// 2-+ 추가된. ETW 이벤트 추가
			ETW_Manager.SetupETWTraceByProviders(parallel_RecieveQueues[EDR::EventLog::Enum::QueueTypes::Queue_ETW]); // 프로바이더 연결
			ETW_Manager.StartETWTrace();

			
			
#define LogClosingEND "_____END"


			/*
			
				Receive by [ Kernel + User ] 

			*/
			for (int i = 0; i < parallel_RecieveQueueThread_Count; i++)
			{
				std::cout << "[receive thread]  MyQueueType: " << i << " Loaded " << std::endl;
				parallel_RecieveQueueThread.push_back(
					std::move(
						std::thread(
							[this, test = &ioctl, is_threading = &is_threading, queue = this->parallel_RecieveQueues[i] ]()
							{
								while (*is_threading)
								{
									auto Log = queue->get();

									auto LogDataType = Log.LogDataType;
									auto Type = Log.Type;
									auto LogData = Log.logData;
									auto LogDataSize = Log.logSize;


									if (LogDataType == EDR::EventLog::Enum::EventLog_LogData_Type::LengthBased)
									{
										try
										{
											SIZE_T currentOffset = 0;
											while (currentOffset < LogDataSize)
											{
												PUCHAR eventPtr = LogData + currentOffset;

												if (currentOffset + sizeof(SIZE_T) > LogDataSize)
													break;

												SIZE_T eventStart = currentOffset;

												// LogType 구하기
												auto LogType = *reinterpret_cast<const EDR::EventLog::Enum::EventLog_Enum*>(eventPtr); // 8byte to 4byte

												// Parameter담을 벡터 (Varient)
												std::vector<
													std::variant<
													ULONG64, ULONG32, BOOLEAN, HANDLE, std::string
													>
												>Parameters;

												// goNext
												currentOffset += sizeof(SIZE_T);

												// Parameter 들 구하기 ( _____END 찾을 떄까지 ) 
												ULONG32 index = 0;
												while (true)
												{
													if (currentOffset + 8 <= LogDataSize &&
														RtlCompareMemory(LogData + currentOffset, LogClosingEND, 8) == 8)
													{
														// 이벤트 끝
														currentOffset += 8;  // end string skip
														break;
													}

													//
													// 데이터 길이 읽기(Size)
													//
													if (currentOffset + sizeof(SIZE_T) > LogDataSize)
														goto END_PARSE;

													SIZE_T dataSize = *(SIZE_T*)(LogData + currentOffset);
													currentOffset += sizeof(SIZE_T);

													//
													// 실제 데이터 스킵
													//
													if (currentOffset + dataSize > LogDataSize)
														goto END_PARSE;

													PUCHAR dataPtr = LogData + currentOffset; // RealData


													//데이터 삽입




												// [ 공통 ]

													if (index == 0)
														Parameters.push_back(*(HANDLE*)dataPtr);					// 1. PROCESS ID

													else if (index == 1)
														Parameters.push_back(*(ULONG64*)dataPtr);					// 2. NanoTimestamp

													else
													{
														// [ Event별 ]
														switch (LogType)
														{
														case EDR::EventLog::Enum::EventLog_Enum::Process_Create:
														{
															switch (index)
															{
															case 2:
															{
																Parameters.push_back(*(HANDLE*)dataPtr);			// 3. PARENT PROCESS ID
																break;
															}
															case 3:
															{
																auto CommandLine = PwchToString((PWCH)dataPtr);
																Parameters.push_back(CommandLine);					// 4. CommandLine
																break;
															}
															case 4:
															{
																auto SID = PwchToString((PWCH)dataPtr);
																Parameters.push_back(SID);							// 5. SID
																break;
															}
															case 5:
															{
																auto ImagePath = PwchToString((PWCH)dataPtr);
																Parameters.push_back(ImagePath);					// 6. ImagePath
																break;
															}
															case 6:
															{
																Parameters.push_back(*(ULONG64*)dataPtr);			// 7. ImageSize
																break;
															}
															case 7:
															{
																auto ImageSHA256 = std::string((PCHAR)dataPtr);
																Parameters.push_back(ImageSHA256);					// 8. ImageSha256
																break;
															}
															case 8:
															{
																auto ImagePath = PwchToString((PWCH)dataPtr);
																Parameters.push_back(ImagePath);					// 9. ParentImagePath
																break;
															}
															case 9:
															{
																Parameters.push_back(*(ULONG64*)dataPtr);			// 10. ParentImageSize
																break;
															}
															case 10:
															{
																auto ImageSHA256 = std::string((PCHAR)dataPtr);
																Parameters.push_back(ImageSHA256);					// 11. ParentImageSha256

																std::cout << "ImagePath: " << std::get<std::string>(Parameters[5]) << " [Parent]ImageSHA256: " << ImageSHA256 << std::endl;




																// Process Session Create
																std::string root_SessionID;
																std::string SessionID;
																std::string parent_SessionID;

																ProcessSessionManager.ProcessCreate(
																	std::get<HANDLE>(Parameters[0]),	// Self PID
																	std::get<HANDLE>(Parameters[2]),	// Parent PID
																	std::get < std::string > (Parameters[8]),	// Parent ImagePath
																	SessionID,
																	root_SessionID,
																	parent_SessionID
																);
																if (SessionID.empty())
																	break;
																//std::cout << "std::get<std::string>(Parameters[4]): " << std::get<std::string>(Parameters[4]) << std::endl;
																std::string Username;
																EDR::Util::Windows::SID_to_Username(
																	std::get<std::string>(Parameters[4]),
																	Username
																);

																try
																{
																	// Log to Kafka
																	WindowsLogSender.Send_Log_Process_Create(
																		SessionID,
																		root_SessionID,
																		parent_SessionID,
																		std::get<std::string>(Parameters[4]),
																		Username,
																		OS_VERSION,

																		std::get<HANDLE>(Parameters[0]),
																		std::get<std::string>(Parameters[5]),
																		std::get<ULONG64>(Parameters[6]),
																		std::get<std::string>(Parameters[7]),
																		std::get<HANDLE>(Parameters[2]),
																		std::get<std::string>(Parameters[8]),
																		std::get<ULONG64>(Parameters[9]),
																		std::get<std::string>(Parameters[10]),
																		std::get<std::string>(Parameters[3]),
																		std::get<ULONG64>(Parameters[1])
																	);
																}
																catch (const std::exception& e)
																{
																	std::cout << "KAFKA ERROR:" << e.what() << std::endl;
																}


																break;
															}


															}
															break;
														}

														case EDR::EventLog::Enum::EventLog_Enum::Process_Terminate:
														{

															switch (index)
															{
															case 2:
															{
																std::string root_SessionID;
																std::string SessionID;
																std::string parent_SessionID;

																ProcessSessionManager.ProcessRemove(
																	std::get<HANDLE>(Parameters[0]),
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
																	OS_VERSION,

																	std::get<HANDLE>(Parameters[0]),
																	std::get<ULONG64>(Parameters[1])
																);
																break;
															}
															}

															break;
														}

														case EDR::EventLog::Enum::EventLog_Enum::ImageLoad:
														{
															switch (index)
															{
															case 2:
															{
																auto imagePath = PwchToString((PWCH)dataPtr);
																Parameters.push_back(imagePath);					// 3. ImagePath
																break;
															}
															case 3:
															{
																Parameters.push_back(*(ULONG64*)dataPtr);			// 4. ImageSize
																break;
															}
															case 4:
															{
																auto ImageSha256 = std::string((PCHAR)dataPtr);
																Parameters.push_back(ImageSha256);					// 5. ImageSha256

																{
																	std::string root_SessionID;
																	std::string SessionID;
																	std::string parent_SessionID;

																	ProcessSessionManager.AppendingEvent(
																		std::get<HANDLE>(Parameters[0]),
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

																		OS_VERSION,
																		std::get<HANDLE>(Parameters[0]),

																		std::get<std::string>(Parameters[2]),
																		std::get<ULONG64>(Parameters[3]),
																		std::get<std::string>(Parameters[4]),

																		std::get<ULONG64>(Parameters[1])
																	);
																}
																break;
															}
															}

															break;
														}


														case EDR::EventLog::Enum::EventLog_Enum::Network:
														{
															switch (index)
															{
															case 2:
															{
																Parameters.push_back(*(ULONG32*)dataPtr);		// 3. Protocol Number
																break;
															}
															case 3:
															{
																Parameters.push_back(*(BOOLEAN*)dataPtr);		// 4. is_inbound?
																break;
															}
															case 4:
															{
																Parameters.push_back(*(ULONG32*)dataPtr);		// 5. PacketSize
																break;
															}
															case 5:
															{
																Parameters.push_back(*(ULONG32*)dataPtr);		// 6. NetworkInterfaceIndex
																break;
															}
															case 6:
															{
																auto SourceMacAddress = std::string((PCHAR)dataPtr);
																Parameters.push_back(SourceMacAddress);			// 7. SourceMacAddress
																break;
															}
															case 7:
															{
																auto DestinationMacAddress = std::string((PCHAR)dataPtr);
																Parameters.push_back(DestinationMacAddress);	// 8. DestinationMacAddress
																break;
															}
															case 8:
															{
																auto LOCAL_IP = std::string((PCHAR)dataPtr);
																Parameters.push_back(LOCAL_IP);					// 9. LOCAL_IP
																break;
															}
															case 9:
															{
																Parameters.push_back(*(ULONG32*)dataPtr);				// 10. LOCAL_PORT
																break;
															}
															case 10:
															{
																auto REMOTE_IP = std::string((PCHAR)dataPtr);
																Parameters.push_back(REMOTE_IP);					// 11. REMOTE_IP
																break;
															}
															case 11:
															{
																Parameters.push_back(*(ULONG32*)dataPtr);				// 12. REMOTE_PORT
																break;
															}
															case 12:
															{
																PUCHAR PacketFrameBaseAddress = dataPtr;
																ULONG32 PacketFrameSize = dataSize;
																//Parameters.push_back(*(ULONG32*)dataPtr);				// 13. RealPacketFrame

																std::string root_SessionID;
																std::string SessionID;
																std::string parent_SessionID;


																
																// [ 프로세스 세션 ]
																ProcessSessionManager.AppendingEvent(
																	std::get<HANDLE>(Parameters[0]),
																	SessionID,
																	root_SessionID,
																	parent_SessionID
																);
																if (SessionID.empty())
																	break;


																// [ 네트워크 세션 ]
																bool is_new_session = false;
																EDR::Session::Network::NetworkSessionInfo Network_SessionINFO;
																NetworkSessionManager.Get_NetworkSessionInfo(
																	std::get<HANDLE>(Parameters[0]),

																	std::get<ULONG32>(Parameters[2]),
																	std::get<std::string>(Parameters[8]),
																	std::get<ULONG32>(Parameters[9]),
																	std::get<std::string>(Parameters[10]),
																	std::get<ULONG32>(Parameters[11]),

																	Network_SessionINFO,
																	&is_new_session
																);

																if (std::get<ULONG32>(Parameters[2]) == 1)
																{
																	std::cout << "[PRE] NETWORK: LOCAL: " << std::get<std::string>(Parameters[8]) << " -> " << "REMOTE: " << std::get<std::string>(Parameters[10]) << std::endl;
																}

																//
																if (!is_new_session)
																	// 로그 과부화 방지를 위해 최초 감지된 세션말고는 전송안함,
																	break;

																if (std::get<ULONG32>(Parameters[2]) == 1)
																{
																	std::cout << "[POST] NETWORK: LOCAL: " << std::get<std::string>(Parameters[8]) << " -> " << "REMOTE: " << std::get<std::string>(Parameters[10]) << std::endl;
																}

																Network_SessionINFO.SessionID;
																Network_SessionINFO.first_seen_nanotimestamp;
																Network_SessionINFO.last_seen_nanotimestamp;

																//std::cout << NetworkLog->body.ProtocolNumber << " || " << (NetworkLog->body.is_INBOUND ? "In" : "out") << " || " << NetworkLog->body.PacketSize << "PacketNetworkSessionID:" << Network_SessionINFO.SessionID << std::endl;

																// logSend
																WindowsLogSender.Send_Log_Network(
																	SessionID,
																	root_SessionID,
																	parent_SessionID,

																	OS_VERSION,
																	std::get<HANDLE>(Parameters[0]),

																	std::get<ULONG32>(Parameters[5]),
																	std::get<std::string>(Parameters[6]),
																	std::get<std::string>(Parameters[7]),
																	std::get<std::string>(Parameters[8]),
																	std::get<ULONG32>(Parameters[9]),
																	std::get<std::string>(Parameters[10]),
																	std::get<ULONG32>(Parameters[11]),
																	std::get<BOOLEAN>(Parameters[3]),
																	std::get<ULONG32>(Parameters[4]),
																	ProtocolToString(std::get<ULONG32>(Parameters[2])),

																	std::get<ULONG64>(Parameters[1]),

																	Network_SessionINFO.SessionID,
																	Network_SessionINFO.first_seen_nanotimestamp,
																	Network_SessionINFO.last_seen_nanotimestamp
																);

																break;
															}
															}

															break;
														}

														case EDR::EventLog::Enum::EventLog_Enum::Filesystem:
														{
															switch (index)
															{
															case 2:
															{
																std::string FileAction;
																switch (*(EDR::EventLog::Enum::FileSystem::Filesystem_enum*)dataPtr)
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
																case EDR::EventLog::Enum::FileSystem::execute:
																	FileAction = "execute";
																	break;
																case EDR::EventLog::Enum::FileSystem::create_directory:
																	FileAction = "create_directory";
																	break;
																case EDR::EventLog::Enum::FileSystem::remove_directory:
																	FileAction = "remove_directory";
																	break;
																case EDR::EventLog::Enum::FileSystem::rename_directory:
																	FileAction = "rename_directory";
																	break;
																default:
																	throw std::runtime_error("Filesystem error");
																}


																Parameters.push_back(FileAction);		// 3. File Action STRING
																break;
															}
															case 3:
															{
																auto FilePath = PwchToString((PWCH)dataPtr);
																Parameters.push_back(FilePath);			// 4. FilePath
																break;
															}
															case 4:
															{
																auto RenameFilePath = PwchToString((PWCH)dataPtr);
																if (RenameFilePath == "none") RenameFilePath = "";
																Parameters.push_back(RenameFilePath);			// 5. Rename_FilePath
																break;
															}
															case 5:
															{
																auto FileSha256 = std::string((PCHAR)dataPtr);
																if (FileSha256 == "none") FileSha256 = "";
																Parameters.push_back(FileSha256);				// 6. Sha256
																break;
															}
															case 6:
															{
																Parameters.push_back(*(ULONG64*)dataPtr);		// 7. FileSize


																std::string root_SessionID;
																std::string SessionID;
																std::string parent_SessionID;

																ProcessSessionManager.AppendingEvent(
																		std::get<HANDLE>(Parameters[0]),
																		SessionID,
																		root_SessionID,
																		parent_SessionID
																	);
																	if (SessionID.empty())
																		break;

																		// LogSend
																WindowsLogSender.Send_Log_FileSystem(
																	SessionID,
																	root_SessionID,
																	parent_SessionID,

																	OS_VERSION,
																	std::get<HANDLE>(Parameters[0]),

																	std::get<std::string>(Parameters[2]),
																	std::get<std::string>(Parameters[3]),
																	std::get<std::string>(Parameters[5]),
																	std::get<ULONG64>(Parameters[6]),
																	std::get<std::string>(Parameters[4]),

																	std::get<ULONG64>(Parameters[1])
																);


																break;
															}


															}
															break;
														}

														case EDR::EventLog::Enum::ObRegisterCallback:
														{
															switch (index)
															{
															case 2:
															{
																Parameters.push_back(*(ULONG32*)dataPtr);				// 3. DesiredAccess 
																break;
															}
															case 3:
															{
																Parameters.push_back(*(BOOLEAN*)dataPtr);				// 4. is_CreateHandle 
																break;
															}
															case 4:
															{
																Parameters.push_back(*(HANDLE*)dataPtr);				// 5. TargetProcessId 

																std::string root_SessionID;
																std::string SessionID;
																std::string parent_SessionID;

																/*ProcessSessionManager.AppendingEvent(
																		std::get<HANDLE>(Parameters[0]),
																		SessionID,
																		root_SessionID,
																		parent_SessionID
																	);
																	if (SessionID.empty())
																		break;*/

																std::vector<std::string> DesiredAccessVec;
																auto Desired = std::get<ULONG32>(Parameters[2]);
																if (Desired & PROCESS_ALL_ACCESS)
																	DesiredAccessVec.push_back("PROCESS_ALL_ACCESS");


#define PROCESS_SYNCHRONIZE                0x00100000
																if (Desired & PROCESS_CREATE_PROCESS)
																	DesiredAccessVec.push_back("PROCESS_CREATE_PROCESS");
																if (Desired & PROCESS_CREATE_THREAD)
																	DesiredAccessVec.push_back("PROCESS_CREATE_THREAD");
																if (Desired & PROCESS_DUP_HANDLE)
																	DesiredAccessVec.push_back("PROCESS_DUP_HANDLE");
																if (Desired & PROCESS_QUERY_INFORMATION)
																	DesiredAccessVec.push_back("PROCESS_QUERY_INFORMATION");
																if (Desired & PROCESS_QUERY_LIMITED_INFORMATION)
																	DesiredAccessVec.push_back("PROCESS_QUERY_LIMITED_INFORMATION");
																if (Desired & PROCESS_SET_INFORMATION)
																	DesiredAccessVec.push_back("PROCESS_SET_INFORMATION");
																if (Desired & PROCESS_SET_QUOTA)
																	DesiredAccessVec.push_back("PROCESS_SET_QUOTA");
																if (Desired & PROCESS_SUSPEND_RESUME)
																	DesiredAccessVec.push_back("PROCESS_SUSPEND_RESUME");
																if (Desired & PROCESS_TERMINATE)
																	DesiredAccessVec.push_back("PROCESS_TERMINATE");
																if (Desired & PROCESS_VM_OPERATION)
																	DesiredAccessVec.push_back("PROCESS_VM_OPERATION");
																if (Desired & PROCESS_VM_READ)
																	DesiredAccessVec.push_back("PROCESS_VM_READ");
																if (Desired & PROCESS_VM_WRITE)
																	DesiredAccessVec.push_back("PROCESS_VM_WRITE");
																if (Desired & PROCESS_SET_LIMITED_INFORMATION)
																	DesiredAccessVec.push_back("PROCESS_SET_LIMITED_INFORMATION");
																if (Desired & PROCESS_SYNCHRONIZE)
																	DesiredAccessVec.push_back("PROCESS_SYNCHRONIZE");

																// 표준 권한
																if (Desired & DELETE)
																	DesiredAccessVec.push_back("DELETE");
																if (Desired & READ_CONTROL)
																	DesiredAccessVec.push_back("READ_CONTROL");
																if (Desired & WRITE_DAC)
																	DesiredAccessVec.push_back("WRITE_DAC");
																if (Desired & WRITE_OWNER)
																	DesiredAccessVec.push_back("WRITE_OWNER");

																// Generic
																if (Desired & GENERIC_READ)
																	DesiredAccessVec.push_back("GENERIC_READ");
																if (Desired & GENERIC_WRITE)
																	DesiredAccessVec.push_back("GENERIC_WRITE");
																if (Desired & GENERIC_EXECUTE)
																	DesiredAccessVec.push_back("GENERIC_EXECUTE");
																if (Desired & GENERIC_ALL)
																	DesiredAccessVec.push_back("GENERIC_ALL");


																WindowsLogSender.Send_Log_ProcessAccess(
																	SessionID,
																	root_SessionID,
																	parent_SessionID,

																	OS_VERSION,
																	std::get<HANDLE>(Parameters[0]),

																	std::get<BOOLEAN>(Parameters[3]) ? "create" : "duplicate",
																	std::get<HANDLE>(Parameters[4]),
																	DesiredAccessVec,

																	std::get<ULONG64>(Parameters[1])
																);

																break;
															}
															}
															break;
														}

														case EDR::EventLog::Enum::Registry_CompleteNameLog:
														{
															switch (index)
															{
															case 2:
															{
																auto KeyClass = std::string((PCHAR)dataPtr);
																Parameters.push_back(KeyClass);				// 3. KeyClass 
																break;
															}
															case 3:
															{

																auto CompleteName = PwchToString((PWCH)dataPtr);
																if (CompleteName == "none") CompleteName = "";
																Parameters.push_back(CompleteName);				// 4. CompleteName 


																{
																	std::string root_SessionID;
																	std::string SessionID;
																	std::string parent_SessionID;

																	/*ProcessSessionManager.AppendingEvent(
																		std::get<HANDLE>(Parameters[0]),
																		SessionID,
																		root_SessionID,
																		parent_SessionID
																	);
																	if (SessionID.empty())
																		break;*/
																	WindowsLogSender.Send_Log_Registry(
																		SessionID,
																		root_SessionID,
																		parent_SessionID,

																		OS_VERSION,
																		std::get<HANDLE>(Parameters[0]),

																		std::get<std::string>(Parameters[2]),
																		std::get<std::string>(Parameters[3]),

																		std::get<ULONG64>(Parameters[1])
																	);

																}

																break;
															}
															}
															break;
														}

														case EDR::EventLog::Enum::Registry_OldNewLog:
														{
															switch (index)
															{
															case 2:
															{
																auto KeyClass = std::string((PCHAR)dataPtr);
																Parameters.push_back(KeyClass);				// 3. KeyClass 
																break;
															}
															case 3:
															{
																auto Name = PwchToString((PWCH)dataPtr);
																if (Name == "none") Name = "";
																Parameters.push_back(Name);				// 4. Name 
																break;
															}
															case 4:
															{
																auto New = PwchToString((PWCH)dataPtr);
																if (New == "none") New = "";
																Parameters.push_back(New);				// 5. New 
																break;
															}
															case 5:
															{
																auto Old = PwchToString((PWCH)dataPtr);
																if (Old == "none") Old = "";
																Parameters.push_back(Old);				// 6. Old 


																{
																	std::string root_SessionID;
																	std::string SessionID;
																	std::string parent_SessionID;

																	/*ProcessSessionManager.AppendingEvent(
																		std::get<HANDLE>(Parameters[0]),
																		SessionID,
																		root_SessionID,
																		parent_SessionID
																	);
																	if (SessionID.empty())
																		break;*/

																	WindowsLogSender.Send_Log_Registry(
																		SessionID,
																		root_SessionID,
																		parent_SessionID,

																		OS_VERSION,
																		std::get<HANDLE>(Parameters[0]),

																		std::get<std::string>(Parameters[2]),
																		std::get<std::string>(Parameters[3]),
																		std::get<std::string>(Parameters[4]),
																		std::get<std::string>(Parameters[5]),

																		std::get<ULONG64>(Parameters[1])
																	);
																}


																break;
															}
															}
															break;
														}

														}
													}



													currentOffset += dataSize;
													++index;
												}

											}
										}
										catch (const std::exception& e)
										{
											std::cout << "ERROR: " << e.what() << std::endl;
										}


										goto END_PARSE;
									}
									else if (LogDataType == EDR::EventLog::Enum::EventLog_LogData_Type::StructBased)
									{

										switch (Log.Type)
										{
										case EDR::EventLog::Enum::EventLog_Enum::etw:
										{

											EDR::EventLog::Struct::ETW::ETW_Log_Struct* ETWLog =
												reinterpret_cast<EDR::EventLog::Struct::ETW::ETW_Log_Struct*>(Log.logData);

											/*
											std::cout << "===== ETW EVENT LOG =====" << std::endl;



											std::cout << "Provider Name : " << ETWLog->ProviderName << std::endl;
											std::cout << "Event Name    : " << ETWLog->EventName << std::endl;
											std::cout << "Event ID      : " << ETWLog->EventId << std::endl;
											std::cout << "Event Version : " << ETWLog->EventVersion << std::endl;
											std::cout << "Event Flags   : " << ETWLog->EventFlags << std::endl;
											std::cout << "Process ID    : " << ETWLog->header.ProcessId << std::endl;
											std::cout << "Timestamp(ns) : " << ETWLog->header.NanoTimestamp << std::endl;

											std::cout << "Field Count   : " << ETWLog->field.FieldCount << std::endl;
											*/

											std::string fieldsJson;
											for (unsigned long index = 0; index < ETWLog->field.FieldCount; index++)
											{
												const auto& field = ETWLog->field.Fields[index];

												//std::cout << "  [Field " << index << "]" << std::endl;
												//std::cout << "    Name  : " << field.FieldName << std::endl;
												//std::cout << "    Value : " << field.FieldValue << std::endl;

												// JSON 문자열에 추가
												fieldsJson += fmt::format("\"{}\": \"{}\"", escape_json(field.FieldName), escape_json(field.FieldValue));
												if (index < ETWLog->field.FieldCount - 1)
													fieldsJson += ", ";
											}

											//std::cout << "==========================" << std::endl;



											std::string root_SessionID;
											std::string SessionID;
											std::string parent_SessionID;
											ProcessSessionManager.AppendingEvent(
																	ETWLog->header.ProcessId,
																	SessionID,
																	root_SessionID,
																	parent_SessionID
																);
																if (SessionID.empty())
																	break;

																	//std::cout << "Process ID    : " << ETWLog->header.ProcessId << std::endl;

											WindowsLogSender.Send_Log_ETW(
												SessionID,
												root_SessionID,
												parent_SessionID,

												ETWLog->header.ProcessId,

												ETWLog->ProviderName,
												ETWLog->EventName,
												ETWLog->EventVersion,
												ETWLog->EventId,
												ETWLog->EventFlags,

												fieldsJson,

												ETWLog->header.NanoTimestamp

											);
										}
										default:
										{
											break;
										}
										}

										goto END_PARSE;

									}


									END_PARSE:
									{
										//if (LogDataType == EDR::EventLog::Enum::EventLog_LogData_Type::LengthBased)
										//else
										//	delete[] Log.logData;
										VirtualFree(Log.logData, 0, MEM_RELEASE);
										continue;
									}


								}
							}
						)
					)
				);
				parallel_RecieveQueueThread[i].detach();
			}

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


std::string PwchToString(PWCH pwch)
{
	if (!pwch)
		return "";

	// 먼저 필요한 버퍼 크기 계산
	int size_needed = WideCharToMultiByte(
		CP_UTF8,            // UTF-8로 변환
		0,                  // 변환 옵션
		pwch,               // 입력 WCHAR*
		-1,                 // null-terminated
		nullptr,            // 출력 버퍼 없음
		0,                  // 출력 버퍼 크기
		nullptr, nullptr    // 기본 문자 사용 X
	);

	if (size_needed <= 0)
		return "";

	std::string result(size_needed, 0);
	WideCharToMultiByte(
		CP_UTF8,
		0,
		pwch,
		-1,
		&result[0],
		size_needed,
		nullptr, nullptr
	);

	// WideCharToMultiByte는 null 문자까지 포함하므로 마지막 null 제거
	if (!result.empty() && result.back() == '\0') {
		result.pop_back();
	}

	return result;
}