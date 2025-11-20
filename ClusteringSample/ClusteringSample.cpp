#include <iostream>
#include <thread>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <cstring>
#include <functional>
#include <unistd.h>
#include <arpa/inet.h>
#include <condition_variable>

/* ------------------- UDP SOCKET ------------------- */
namespace EDR::Util::Udp
{
    class UdpClient
    {
    public:
        UdpClient(const std::string& serverIp, unsigned int serverPort)
            : serverIp(serverIp), serverPort(serverPort) {}

        bool Connect()
        {
            if(is_connected) return false;
            sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if(sockfd < 0) { perror("socket"); return false; }

            memset(&serverAddr, 0, sizeof(serverAddr));
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(serverPort);

            if(inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr) <= 0)
            {
                perror("invalid server IP");
                close(sockfd);
                return false;
            }
            is_connected = true;
            return true;
        }

        bool Send(const std::vector<unsigned char>& data)
        {
            if(!is_connected) return false;
            ssize_t sent = sendto(sockfd, data.data(), data.size(), 0,
                                  (struct sockaddr*)&serverAddr, sizeof(serverAddr));
            return sent == (ssize_t)data.size();
        }

        void Close() { if(is_connected) close(sockfd); is_connected = false; }

    private:
        int sockfd = -1;
        std::string serverIp;
        unsigned int serverPort;
        struct sockaddr_in serverAddr{};
        bool is_connected = false;
    };

    class UdpServer
    {
    public:
        UdpServer(const std::string& ip, unsigned int port) : ip(ip), port(port) {}
        
        bool Run(std::function<void(const std::string&, std::vector<unsigned char>&)> callback)
        {
            sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if(sockfd < 0) { perror("socket"); return false; }

            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

            if(bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
            {
                perror("bind"); return false;
            }

            receiver_thread = std::thread([this, callback]() {
                while(running)
                {
                    unsigned char buffer[1500];
                    struct sockaddr_in clientAddr{};
                    socklen_t len = sizeof(clientAddr);
                    ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                         (struct sockaddr*)&clientAddr, &len);
                    if(n > 0)
                    {
                        std::vector<unsigned char> data(buffer, buffer + n);
                        char clientIp[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, INET_ADDRSTRLEN);
                        callback(std::string(clientIp), data);
                    }
                }
            });
            running = true;
            return true;
        }

        void Stop()
        {
            running = false;
            close(sockfd);
            if(receiver_thread.joinable()) receiver_thread.join();
        }

    private:
        int sockfd;
        std::string ip;
        unsigned int port;
        std::thread receiver_thread;
        bool running = false;
    };
}

/* ------------------- MASTER / SLAVE ------------------- */
enum CMD { Hello = 1, Update = 2 };

struct NodePacket
{
    uint32_t nodeId;
    char ipv4[16];
    uint32_t port;
};

class ClusteringNode
{
public:
    ClusteringNode(bool isMaster, unsigned int nodeId, const std::string& ip, unsigned int port,
                   const std::string& masterIp = "", unsigned int masterPort = 0)
        : isMaster(isMaster), nodeId(nodeId), ip(ip), port(port), masterIp(masterIp), masterPort(masterPort)
    {
        udpServer = new EDR::Util::Udp::UdpServer(ip, port);
        udpServer->Run([this](const std::string& fromIp, std::vector<unsigned char>& data) {
            handle_receive(fromIp, data);
        });

        if(!isMaster)
            hello_master();
    }

    ~ClusteringNode()
    {
        udpServer->Stop();
        delete udpServer;
    }

private:
    bool isMaster;
    unsigned int nodeId;
    std::string ip;
    unsigned int port;

    std::string masterIp;
    unsigned int masterPort;

    EDR::Util::Udp::UdpServer* udpServer;
    std::mutex mapMutex;
    std::map<unsigned int, NodePacket> nodeMap;

    // for slave
    bool is_waiting_for_master = false;
    std::condition_variable hello_cv;
    std::mutex hello_mtx;

    void handle_receive(const std::string& fromIp, std::vector<unsigned char>& data)
    {
        if(data.empty()) return;
        CMD cmd = static_cast<CMD>(data[0]);
        if(cmd == Hello && isMaster)
        {
            // Master는 Hello 받으면 Update 보내기
            NodePacket np{};
            np.nodeId = nodeId;
            strncpy(np.ipv4, ip.c_str(), sizeof(np.ipv4));
            np.port = port;

            // map에 저장
            nodeMap[np.nodeId] = np;

            std::vector<unsigned char> updateBuf;
            updateBuf.push_back(static_cast<unsigned char>(Update));
            updateBuf.insert(updateBuf.end(),
                             (unsigned char*)&np,
                             (unsigned char*)&np + sizeof(np));
            EDR::Util::Udp::UdpClient client(fromIp, *(uint16_t*)&data[1]); // 단순히 포트 전송 가정
            client.Connect();
            client.Send(updateBuf);
            std::cout << "[Master] Sent Update to " << fromIp << "\n";
        }
        else if(cmd == Update && !isMaster)
        {
            
            std::unique_lock<std::mutex> lock2(hello_mtx);
            if(is_waiting_for_master)
            {
                is_waiting_for_master = false;
                hello_cv.notify_one();
            }
                

            NodePacket np{};
            memcpy(&np, &data[1], sizeof(np));
            std::lock_guard<std::mutex> lock(mapMutex);
            nodeMap[np.nodeId] = np;
            std::cout << "[Slave] Received Update from Master: " << np.ipv4 << ":" << np.port << "\n";
        }
    }

    bool hello_master()
    {
        EDR::Util::Udp::UdpClient client(masterIp, masterPort);
        client.Connect();

        std::vector<unsigned char> buf;
        buf.push_back(static_cast<unsigned char>(Hello));
        buf.insert(buf.end(), (unsigned char*)&port, (unsigned char*)&port + sizeof(port));

        client.Send(buf);
        is_waiting_for_master = true;
        std::unique_lock<std::mutex> lock(hello_mtx);
        std::cout << "[Slave] Sent Hello to Master\n";

        if(hello_cv.wait_for(lock, std::chrono::seconds(2), [this]{ return !is_waiting_for_master; }))
        {
            std::cout << "[Slave] Update received, ready\n";
            return true;
        }
        else
        {
            std::cout << "[Slave] Update Receive Failed... " << std::endl;
            return false;
        }
        
    }
};

/* ------------------- MAIN ------------------- */
int main(int argc, char** argv)
{
    if(argc < 2)
    {
        std::cout << "Usage: ./app master|slave [master_ip] [master_port]\n";
        return 0;
    }

    std::string role = argv[1];

    if(role == "master")
    {
        ClusteringNode master(true, 1, "127.0.0.1", 9000);
        std::cout << "Master running...\n";
        while(true) std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    else if(role == "slave")
    {
        if(argc < 4)
        {
            std::cout << "Usage: ./app slave master_ip master_port\n";
            return 0;
        }
        std::string masterIp = argv[2];
        unsigned int masterPort = std::stoi(argv[3]);

        ClusteringNode slave(false, 2, "127.0.0.1", 9001, masterIp, masterPort);
        std::cout << "Slave running...\n";
        while(true) std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}
