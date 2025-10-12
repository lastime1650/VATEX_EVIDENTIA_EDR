#ifndef EDR_C2C_HPP
#define EDR_C2C_HPP

#include "Util.hpp"
#include "IOCTL.hpp"


namespace EDR
{
	namespace C2C
	{
		namespace Enum
		{
			enum EDRC2C_ENUM
			{
				RequestFileBin = 1,
				RequestResponse_PROCESS,
				RequestResponse_NETWORK,
				RequestResponse_FILE
			};
		}
		class EDRC2C
		{
		public:
			EDRC2C(
				std::string& AGENT_ID,
				EDR::IOCTL::Log_IOCTL& ioctl
			) :
				AGENT_ID(AGENT_ID),
				ioctl(ioctl)
			{

			}
			~EDRC2C() { Stop(); }

			bool Run(std::string arg_EDR_TCP_SERVER_IP, unsigned int arg_EDR_TCP_SERVER_PORT, unsigned int retry_count = INFINITE)
			{
				if (is_running)
					return false;

				EDR_TCP_SERVER_IP = arg_EDR_TCP_SERVER_IP;
				EDR_TCP_SERVER_PORT = arg_EDR_TCP_SERVER_PORT;

				is_running = true;
				running_thread = std::thread(
					[this, is_run = &this->is_running, agentid = this->AGENT_ID, arg_EDR_TCP_SERVER_IP, arg_EDR_TCP_SERVER_PORT, retry_count]()
					{
						std::cout << "[EDRC2C] Runing TCP Thread" << std::endl;
						unsigned int tmp_retry_count = 0;

						EDR::Util::Tcp::TcpManager TM(arg_EDR_TCP_SERVER_IP, arg_EDR_TCP_SERVER_PORT);

						std::vector<unsigned char> TcpReceiveBuffer;
						while (*is_run)
						{
							if (TM.Connect())
							{
								std::cout << "EDR TCP SERVER Connected" << std::endl; 
								std::cout << "Sending to AGENT INITIALIZE Information to EDR ..." << std::endl;
								// initialize send to EDR
								std::string msg = json(
									{
										{"agentid", agentid}
									}
								).dump();
								if (!TM.Send(std::vector<uint8_t>(msg.begin(), msg.end())))
								{
									std::cout << "send failed the INITIALIZE information to EDR" << std::endl;
									continue;
								}
								std::cout << "complete" << std::endl;
								std::string JSON_str_Command;
								json Command;
								std::string send_result;
								while (*is_run)
								{
									// loop receive
									TM.Receive(TcpReceiveBuffer);
									if (TcpReceiveBuffer.empty())
									{
										std::cout << "[EDRC2C] TcpReceiveBuffer.empty()" << std::endl;
										goto FAILED;
									}
									
									JSON_str_Command = std::string(TcpReceiveBuffer.begin(), TcpReceiveBuffer.end());
									if (JSON_str_Command.empty())
									{
										std::cout << "[EDRC2C] JSON_Command.empty()" << std::endl;
										goto FAILED;
									}

									Command = json::parse(JSON_str_Command);
									if (Command.empty())
									{
										std::cout << "[EDRC2C] Command.empty()" << std::endl;
										goto FAILED;
									}

									// json key 검증
									if (!Command.contains("agentid") || !Command.contains("cmd") || !Command.contains("parameter"))
									{
										std::cout << "[EDRC2C] Command.contains() failed" << std::endl;
										goto FAILED;
									}
									
									// agentid 매치
									if ( Command["agentid"].get<std::string>() != agentid)
									{
										std::cout << "[EDRC2C] Command[agentid] failed" << std::endl;
										goto FAILED;
									}

									switch ((Enum::EDRC2C_ENUM)Command["cmd"].get<int>())
									{
									case  Enum::RequestResponse_PROCESS:
										{
											// parameter key:value 검증
											if (!Command["parameter"].contains("pid") || !Command["parameter"].contains("exe_path"))
											{
												std::cout << "[EDRC2C] Command[RequestResponse_PROCESS] Parameter failed" << std::endl;
												goto FAILED;
											}
											unsigned long long pid = Command["parameter"]["pid"].get<unsigned long long>();
											std::string exe_path = Command["parameter"]["exe_path"].get<std::string>();

											std::cout << "[EDRC2C] PROESS -> pid: " << pid << " exe_path: " << exe_path << std::endl;

											break;
										}
									default:
										{
											std::cout << "[EDRC2C] Command[agentid] failed" << std::endl;
											goto FAILED;
										}
									}


								SUCCESS:
									{
										send_result = json(
											{
												{"result", true}
											}
										).dump();

										TM.Send(std::vector<uint8_t>(send_result.begin(), send_result.end()));
										continue;
									}
								FAILED:
									{
										send_result = json(
											{
												{"result", false}
											}
										).dump();

										TM.Send( std::vector<uint8_t>(send_result.begin(), send_result.end()) );
										continue;
									}
								}
							}
							else
							{
								if (tmp_retry_count < retry_count)
								{
									++tmp_retry_count;
									std::this_thread::sleep_for(std::chrono::seconds(10));
								}
								else {
									break;
								}
								
							}
						}
						*is_run = false;
					}
				);

				return true;
			}
			bool Stop()
			{
				if (!is_running)
					return false;

				is_running = false;
				if (running_thread.joinable())
					running_thread.join();
				return true;
			}

		private:
			bool is_running = false;
			std::thread running_thread;

			std::string& AGENT_ID;
			EDR::IOCTL::Log_IOCTL& ioctl;

			std::string EDR_TCP_SERVER_IP = "";
			unsigned int EDR_TCP_SERVER_PORT = 0;
		};
	}
}

#endif