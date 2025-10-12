#include "TCP.hpp"

namespace EDR
{
	namespace Util
	{
		namespace Tcp
		{
			TcpManager::TcpManager(const std::string ip, int port) : server_ip(ip), server_port(port)
			{
				WSADATA wsaData;
				if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
					throw std::runtime_error("WSAStartup failed");
				}

				sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
				if (sock == INVALID_SOCKET) {
					WSACleanup();
					throw std::runtime_error("Socket creation failed");
				}
			}

			TcpManager::~TcpManager()
			{
				closesocket(sock);
				WSACleanup();
			}

			bool TcpManager::Connect()
			{
				sockaddr_in serverAddr;
				serverAddr.sin_family = AF_INET;
				serverAddr.sin_port = htons(server_port);
				inet_pton(AF_INET, server_ip.c_str(), &serverAddr.sin_addr);

				if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
					return false;
				}
				return true;
			}

			bool TcpManager::Send(const std::vector<unsigned char>& data)
			{
				unsigned int totalSent = 0;
				unsigned int dataSize = static_cast<int>(data.size());
				std::cout << "dataSend... dataSize:" << dataSize << std::endl;

				// 1. 길이값 전송 ( 고정 4바이트 )
				int sent = send(sock, reinterpret_cast<const char*>(  & dataSize ), sizeof(dataSize), 0);
				if (sent == SOCKET_ERROR) {
					std::cout << "TcpManager::Send [1/2] length send failed" << std::endl;
					return false;
				}

				// 2. 데이터 전송
				while (totalSent < dataSize) {
					sent = send(sock, reinterpret_cast<const char*>(data.data() + totalSent), dataSize - totalSent, 0);
					if (sent == SOCKET_ERROR) {
						std::cout << "TcpManager::Send [2/2] data send failed" << std::endl;
						return false;
					}
					totalSent += sent;
				}
				return true;
			}

			bool TcpManager::Receive(std::vector<unsigned char>& buffer)
			{

				// 1. 4바이트 고정 받을 데이터 받기
				unsigned int BufferSize = 0;
				int received = recv(sock, reinterpret_cast<char*>(&BufferSize), sizeof(BufferSize), 0);
				if (received == SOCKET_ERROR || received == 0) {
					return false;
				}
				unsigned int expectedSize = BufferSize;

				buffer.resize(expectedSize); // 공간 할당 벡터
				unsigned int totalReceived = 0;

				while (totalReceived < expectedSize) {
					int received = recv(sock, reinterpret_cast<char*>(buffer.data() + totalReceived), expectedSize - totalReceived, 0);
					if (received == SOCKET_ERROR || received == 0) {
						return false;
					}
					totalReceived += received;
				}
				return true;
			}
		}
	}
}