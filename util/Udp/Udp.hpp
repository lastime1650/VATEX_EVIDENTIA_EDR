#ifndef UDP_SOCKET_HPP
#define UDP_SOCKET_HPP

#include <string>

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <functional>
#include <thread>

namespace EDR
{
	namespace Util
	{
		namespace Udp
		{
			class UdpServer
            {
            public:
                UdpServer(const std::string& UdpServerIp, const unsigned int UdpServerPort)
                :
                UdpServerIp(UdpServerIp),
                UdpServerPort(UdpServerPort)
                {
                    
                }
            
                bool Run( std::function<void( const std::string&, std::vector<unsigned char>, const unsigned long long& ) > DataReceive_Callback, const unsigned long long& SetMaximumReceiveBufferSize = 1500 )
                {
                    if(is_running)
                        return false;

                    struct sockaddr_in server_addr, client_addr;
                    socklen_t addr_len = sizeof(client_addr);

                    // 1. 소켓 생성
                    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                        perror("socket failed");
                        return false;
                    }

                    // 2. 서버 주소 설정
                    struct in_addr addr;
                    if (inet_pton(AF_INET, UdpServerIp.c_str(), &addr) <= 0) {
                        perror("Invalid IP address");
                        close(sockfd);
                        return false;
                    }

                    memset(&server_addr, 0, sizeof(server_addr));
                    server_addr.sin_family = AF_INET;        // IPv4
                    server_addr.sin_addr = addr; // 서버 설정
                    server_addr.sin_port = htons(UdpServerPort);      // 포트 번호

                    // 2+1 타임아웃설정
                    struct timeval tv;
                    tv.tv_sec = 1;      // 1초 타임아웃
                    tv.tv_usec = 0;
                    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

                    // 3. 소켓에 주소 바인딩
                    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                        perror("bind failed");
                        close(sockfd);
                        return false;
                    }

                    is_running = true;
                    ServerRunner = std::thread([this, SetMaximumReceiveBufferSize, addr_len, client_addr, DataReceive_Callback]() mutable {
                        std::vector<unsigned char> buffer(SetMaximumReceiveBufferSize);
                        while (is_running) {
                            ssize_t n = recvfrom(sockfd, buffer.data(), buffer.size(), 0,
                                                (struct sockaddr *)&client_addr, &addr_len);
                            if (n < 0) {
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                    continue; // 타임아웃 발생, 루프 다시 확인

                                if (errno == EINTR || errno == EBADF) // Shutdown 발생확인
                                    break;
                                } else {
                                    perror("recvfrom failed");
                                    break;
                                }
                            }

                            // 클라이언트 IP를 문자열로 변환
                            char ip_buf[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &client_addr.sin_addr, ip_buf, INET_ADDRSTRLEN);
                            std::string client_ip(ip_buf);

                            if (n > 0) {
                                buffer.resize(n);
                                if (DataReceive_Callback) {
                                    DataReceive_Callback(client_ip, buffer, n); // 콜백 호출
                                }
                                buffer.resize(SetMaximumReceiveBufferSize); // 버퍼 초기화
                                //buffer.assign(SetMaximumReceiveBufferSize, 0); // 0 채움
                            }
                        }
                        close(sockfd);
                    });

                    return true;
                }

            bool Stop()
            {
                if(!is_running)
                    return false;

                is_running = false;

                // 블로킹 recvfrom 깨우기
                if(sockfd >= 0)
                {
                    shutdown(sockfd, SHUT_RDWR); // 읽기/쓰기 모두 차단
                }

                if(ServerRunner.joinable())
                    ServerRunner.join();

                return true;
            }

            private:

                bool is_running = false;

                std::string UdpServerIp;
                unsigned int UdpServerPort;   
                 
                int sockfd = -1;

                std::thread ServerRunner;

            };

            class UdpClient
            {
            public:
                UdpClient(const std::string& serverIp, unsigned int serverPort)
                    : serverIp(serverIp), serverPort(serverPort)
                {
                }

                bool Connect()
                {
                    if(is_connected)
                        return false; // already connected

                    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                    if (sockfd < 0) {
                        perror("socket creation failed");
                        is_connected = false;
                        return false;
                    }

                    memset(&serverAddr, 0, sizeof(serverAddr));
                    serverAddr.sin_family = AF_INET;
                    serverAddr.sin_port = htons(serverPort);

                    if (inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr) <= 0) {
                        perror("invalid server IP");
                        close(sockfd);
                        is_connected = false;
                        return false;
                    }

                    is_connected = true;
                    return true;
                }

                bool Send(const std::vector<unsigned char>& data)
                {
                    if(!is_connected)
                        return false;

                    ssize_t sent = sendto(sockfd, data.data(), data.size(), 0,
                                        (struct sockaddr*)&serverAddr, sizeof(serverAddr));
                    return sent == (ssize_t)data.size();
                }

                void Close()
                {
                    if(!is_connected)
                        return;

                    if (sockfd >= 0) {
                        close(sockfd);
                        sockfd = -1;
                    }
                }

                ~UdpClient()
                {
                    Close();
                }

                bool is_connected = false;

            private:
                int sockfd = -1;
                std::string serverIp;
                unsigned int serverPort;
                struct sockaddr_in serverAddr{};

                
            };
        }
    }
}
            

#endif UDP_SERVER_HPP