#ifndef GETNIC_HPP


#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <iostream>
#include "json.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
namespace EDR
{
    namespace Util
    {
        namespace Host
        {
            // NIC 정보 구조체
            struct NICInfo {
                std::string ip;
                std::string mac;
                std::string name;
                std::string gateway;
                ULONG32     ifindex;
            };

            // UTF-16 → UTF-8 변환
            static std::string WideToUtf8(const wchar_t* src)
            {
                if (!src) return {};

                int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, src, -1, nullptr, 0, nullptr, nullptr);
                if (sizeNeeded <= 0) return {};

                std::string result(sizeNeeded - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, src, -1, (LPSTR)result.data(), sizeNeeded, nullptr, nullptr);
                return result;
            }

            // 물리 NIC 여부 판단
            bool IsPhysicalNIC(const IP_ADAPTER_ADDRESSES* a)
            {
                if (!a) return false;

                // 1) IfType: Ethernet 또는 Wi-Fi 만 허용
                if (a->IfType != IF_TYPE_ETHERNET_CSMACD &&
                    a->IfType != IF_TYPE_IEEE80211)
                    return false;

                // 2) 현재 동작 중인지
                if (a->OperStatus != IfOperStatusUp)
                    return false;

                // 3) 물리 MAC 주소가 있어야 함
                if (a->PhysicalAddressLength < 6)
                    return false;

                // 4) IPv4 사용 가능 플래그 (헤더에 정의된 값 사용)
                if ((a->Flags & IP_ADAPTER_IPV4_ENABLED) == 0)
                    return false;

                // 5) Gateway 존재 여부 또는 유효한 글로벌 IPv4 보유
                bool hasGateway = (a->FirstGatewayAddress != nullptr);

                bool hasValidUnicast = false;
                for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                    if (!ua->Address.lpSockaddr) continue;
                    if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;

                    sockaddr_in* sin = (sockaddr_in*)ua->Address.lpSockaddr;
                    uint32_t addr = ntohl(sin->sin_addr.s_addr);

                    // exclude loopback 127.0.0.0/8 and link-local 169.254.0.0/16
                    if ((addr >> 24) == 127) continue;
                    if ((addr >> 16) == 0xA9FE) continue; // 169.254.x.x

                    hasValidUnicast = true;
                    break;
                }

                if (!hasGateway && !hasValidUnicast)
                    return false;

                // (선택적) ConnectionType 검사: 전용 연결이면 더 신뢰
                // 일부 헤더/OS 버전에서는 ConnectionType이 없을 수 있으므로 주석 처리 가능
                // if (a->ConnectionType != NetIfConnectionDedicated) return false;

                return true;
            }

            static std::string GetDefaultGateway(DWORD ifIndex)
            {
                MIB_IPFORWARD_ROW2 route = {};
                SOCKADDR_INET dest = {};
                dest.Ipv4.sin_family = AF_INET;
                InetPton(AF_INET, L"0.0.0.0", &dest.Ipv4.sin_addr);  // Default Route

                SOCKADDR_INET bestSrc = {};

                DWORD ret = GetBestRoute2(
                    nullptr,        // InterfaceLuid, NULL 가능
                    ifIndex,        // InterfaceIndex
                    nullptr,        // SourceAddress, NULL이면 OS가 자동 선택
                    &dest,          // DestinationAddress
                    0,              // AddressSortOptions
                    &route,         // BestRoute
                    &bestSrc        // BestSourceAddress
                );

                if (ret != NO_ERROR)
                    return {};  // 실패 시 빈 문자열 반환

                char buf[INET_ADDRSTRLEN] = { 0 };
                inet_ntop(AF_INET, &route.NextHop.Ipv4.sin_addr, buf, sizeof(buf));

                return std::string(buf);
            }


            static bool GetActiveNICs(std::vector<NICInfo>& outList)
            {
                outList.clear();

                // OS가 선택하는 최우선 NIC (대표 NIC)
                sockaddr_in dest = {};
                dest.sin_family = AF_INET;
                inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr);

                DWORD primaryIdx = 0;
                bool hasPrimary = (GetBestInterfaceEx((sockaddr*)&dest, &primaryIdx) == NO_ERROR);

                ULONG size = 0;
                GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &size);

                auto* addrs = (IP_ADAPTER_ADDRESSES*)malloc(size);
                if (!addrs)
                    return false;

                if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addrs, &size) != NO_ERROR) {
                    free(addrs);
                    return false;
                }

                for (auto* a = addrs; a; a = a->Next)
                {
                    if (!IsPhysicalNIC(a))
                        continue;

                    auto gateway = GetDefaultGateway(a->IfIndex);
                    if (gateway.empty())
                        continue;


                    NICInfo info;

                    // Gateway
                    info.gateway = gateway;

                    // IP (IPv4)
                    for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                        if (ua->Address.lpSockaddr->sa_family != AF_INET)
                            continue;

                        char ipbuf[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET,
                            &((sockaddr_in*)ua->Address.lpSockaddr)->sin_addr,
                            ipbuf, sizeof(ipbuf));

                        info.ip = ipbuf;
                        break;
                    }

                    // MAC
                    if (a->PhysicalAddressLength >= 6) {
                        char macbuf[32];
                        sprintf_s(macbuf, "%02x:%02x:%02x:%02x:%02x:%02x",
                            a->PhysicalAddress[0], a->PhysicalAddress[1],
                            a->PhysicalAddress[2], a->PhysicalAddress[3],
                            a->PhysicalAddress[4], a->PhysicalAddress[5]);

                        info.mac = macbuf;
                    }

                    // FriendlyName (PWCHAR → UTF-8)
                    info.name = WideToUtf8(a->FriendlyName);

                    

                    // ifindex
                    info.ifindex = a->IfIndex;

                    outList.push_back(info);
                }

                free(addrs);

                return !outList.empty();
            }

            static inline nlohmann::json GetActiveNICs_to_Json()
            {
                auto out = nlohmann::json::array();

                std::vector<NICInfo> outList;
                if (!GetActiveNICs(outList))
                    return out;

                for (const auto& nic_info : outList)
                {
                    out.push_back(
                        nlohmann::json::object(
                            {
                                {"ip", nic_info.ip},
                                {"gateway", nic_info.gateway},
                                {"mac", nic_info.mac},
                                {"name", nic_info.name},
                                {"ifindex", nic_info.ifindex}
                            }
                        )
                    );
                }
                return out;
            }
        }
    }
}


#endif