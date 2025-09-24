#ifndef TCP_UTIL_H
#define TCP_UTIL_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>

#pragma comment(lib, "ws2_32.lib")

namespace EDR
{
	namespace Util
	{
		namespace Tcp
		{
			class TcpManager
			{
			public:
				TcpManager(const std::string ip, int port);
				~TcpManager();

				bool Connect();
				bool Send(const std::vector<unsigned char>& inputdata);
				bool Receive(std::vector<unsigned char>& outbuffer);


			private:
				SOCKET sock;
				std::string server_ip;
				int server_port;
			};
		}
	}
}

#endif