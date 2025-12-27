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
                {
                    std::cout << "[EDRC2C] Running TCP Thread" << std::endl;

                    unsigned int tmp_retry_count = 0;

                    while (is_running)
                    {
                        EDR::Util::Tcp::TcpManager TM(arg_EDR_TCP_SERVER_IP, arg_EDR_TCP_SERVER_PORT);

                        if (!TM.Connect())
                        {
                            std::cout << "EDR TCP SERVER Connect failed" << std::endl;

                            if (tmp_retry_count < retry_count)
                            {
                                ++tmp_retry_count;
                                std::this_thread::sleep_for(std::chrono::seconds(10));
                                continue; // 재시도
                            }
                            else
                            {
                                break; // 재시도 횟수 초과
                            }
                        }

                        std::cout << "EDR TCP SERVER Connected" << std::endl;

                        // 초기화 메시지 전송
                        std::string msg = json({
                            {"agentid", AGENT_ID},
                            {"os", "Windows"}
                            }).dump();

                        if (!TM.Send(std::vector<uint8_t>(msg.begin(), msg.end())))
                        {
                            std::cout << "Send INITIALIZE failed, reconnecting..." << std::endl;
                            continue; // 재연결 시도
                        }

                        std::vector<unsigned char> TcpReceiveBuffer;
                        bool connection_alive = true;

                        while (is_running && connection_alive)
                        {
                            if (!TM.Receive(TcpReceiveBuffer) || TcpReceiveBuffer.empty())
                            {
                                std::cout << "[EDRC2C] Receive failed or buffer empty, reconnecting..." << std::endl;
                                connection_alive = false;
                                break;
                            }

                            std::string JSON_str_Command(TcpReceiveBuffer.begin(), TcpReceiveBuffer.end());
                            TcpReceiveBuffer.clear();

                            json Command;
                            try
                            {
                                Command = json::parse(JSON_str_Command);
                            }
                            catch (const std::exception& e)
                            {
                                std::cout << "[EDRC2C] JSON parse failed: " << e.what() << ", reconnecting..." << std::endl;
                                connection_alive = false;
                                break;
                            }

                            // 필수 key 확인
                            /*
                                {
                                    "agentid": "...",
                                    "cmd": int값,
                                    "parameter": {...}
                                }
                            */
                            if (!Command.contains("agentid") || !Command.contains("cmd") || !Command.contains("parameter") ||
                                Command["agentid"].get<std::string>() != AGENT_ID)
                            {
                                std::cout << "[EDRC2C] Command validation failed, reconnecting..." << std::endl;
                                connection_alive = false;
                                break;
                            }

                            switch ((Enum::EDRC2C_ENUM)Command["cmd"].get<int>())
                            {
                            case Enum::RequestResponse_PROCESS:
                            {
                                // 실시간 프로세스 차단

                                /*
                                    1. 프로세스 실행중인 경우, 강제종료
                                    2. 프로세스 파일 삭제.
                                */
                                /*
                                    {
                                        "parameter" : {
                                            "pid": int,
                                            "exe_path": "...." NT PATH
                                        }
                                    }
                                */
                                if (!Command["parameter"].contains("pid") || !Command["parameter"].contains("exe_path"))
                                {
                                    std::cout << "[EDRC2C] Parameter validation failed, reconnecting..." << std::endl;
                                    connection_alive = false;
                                    break;
                                }

                                unsigned long long pid = Command["parameter"]["pid"].get<unsigned long long>();
                                std::string exe_path = Command["parameter"]["exe_path"].get<std::string>();

                                std::cout << "[EDRC2C] PROCESS -> pid: " << pid << " exe_path: " << exe_path << std::endl;

                                // TO EDR
                                std::string send_result = json({ {"result", true} }).dump();
                                TM.Send(std::vector<uint8_t>(send_result.begin(), send_result.end()));
                                break;
                            }
                            case Enum::RequestResponse_FILE:
                            {
                                // 실시간 파일 차단

                                /*
                                    1. 파일 삭제.
                                */
                                /*
                                    {
                                        "parameter" : {
                                            "file_path": "..." NT PATH
                                        }
                                    }
                                */
                                if (!Command["parameter"].contains("file_path"))
                                {
                                    std::cout << "[EDRC2C] Parameter validation failed, reconnecting..." << std::endl;
                                    connection_alive = false;
                                    break;
                                }

                                std::string file_path = Command["parameter"]["file_path"].get<std::string>();

                                // TO EDR
                                std::string send_result = json({ {"result", true} }).dump();
                                TM.Send(std::vector<uint8_t>(send_result.begin(), send_result.end()));

                                break;
                            }
                            default:
                                std::cout << "[EDRC2C] Unknown cmd, reconnecting..." << std::endl;
                                connection_alive = false;
                                break;
                            }
                        }

                        // 연결 종료 처리
                        TM.Disconnect();
                        std::this_thread::sleep_for(std::chrono::seconds(2)); // 재연결 전 약간 대기
                    }

                    is_running = false;
                }


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