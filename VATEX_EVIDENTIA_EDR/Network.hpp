#ifndef NETWORK_H
#define NETWORK_H

#include "util.hpp"

#include <wdm.h>
#include <wdf.h>
#define NDIS630
#include <fwpsk.h>


#include <ndis/nblaccessors.h>
#include <fwpmk.h>

#include <ws2def.h> // IN_ADDR 구조체를 위해 필요
#include <mstcpip.h> // IN_ADDR 구조체를 위해 필요

#include <ip2string.h>

#define NetworkFilter_ALLOC_TAG 'Netx'

namespace EDR
{
	namespace WFP_Filter
	{


		namespace Handler
		{

			extern "C" void FwpsCalloutClassifyFn3(
				_In_ const FWPS_INCOMING_VALUES0* inFixedValues,
				_In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
				_Inout_opt_ void* layerData,
				_In_opt_ const void* classifyContext,
				_In_ const FWPS_FILTER3* filter,
				_In_ UINT64 flowContext,
				_Inout_ FWPS_CLASSIFY_OUT0* classifyOut
			);
		}

        namespace helper
        {
            typedef struct _PARSED_PACKET_INFO {
                // 원본 프레임 데이터 (PCAP 전송용)
                PUCHAR  FrameBuffer; // allocated
                ULONG   FrameSize;

                // 파싱된 정보
                struct
                {
                    BOOLEAN IsIPv4; // if false, ipv6
                    ULONG32 ProtocolNumber;

                    CHAR  LocalIp[16];
                    CHAR  RemoteIp[16];
                    
                }network_layer;
                
                struct
                {

                    BOOLEAN IsTCP; // if false, udp
                    UINT16  LocalPort;
                    UINT16  RemotePort;

                }transport_layer;
                

            } PARSED_PACKET_INFO, * PPARSED_PACKET_INFO; // allocated

            // 이더넷 패킷 바이너리부터 얻기
            BOOLEAN Get_Packet_Size(_In_ void* layerData, _In_ BOOLEAN isInbound, PPARSED_PACKET_INFO* Output); // 동적할당된다.
            VOID Release_Parsed_Packet(_In_ PPARSED_PACKET_INFO packetInfo); // 동적할당해제

        }

		NTSTATUS Load_WFP_Filter(PDEVICE_OBJECT input_device);
		VOID Cleanup_WFP_Filter();
	}
}

// 컴파일러가 구조체 멤버 사이에 패딩을 추가하지 않도록 설정
#pragma pack(push, 1)

//================================================================================
// Layer 2: Ethernet Header
//================================================================================
#define ETHERNET_ADDRESS_LENGTH 6
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IPV6 0x86DD

typedef struct _ETHERNET_HEADER {
    UCHAR DestinationAddress[ETHERNET_ADDRESS_LENGTH];
    UCHAR SourceAddress[ETHERNET_ADDRESS_LENGTH];
    USHORT EtherType; // Network Byte Order (Big Endian)
} ETHERNET_HEADER, * PETHERNET_HEADER;


//================================================================================
// Layer 3: IPv4 Header
//================================================================================
#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP  6
#define IP_PROTOCOL_UDP  17

typedef struct _IPV4_HEADER {
    UCHAR  HeaderLength : 4;    // Length of the header in 32-bit words
    UCHAR  Version : 4;         // IP version number (should be 4)
    UCHAR  TypeOfService;
    USHORT TotalLength;         // Total length of the packet (header + data) in bytes
    USHORT Identification;
    USHORT FlagsAndOffset;      // Flags (3 bits) and Fragment Offset (13 bits)
    UCHAR  TimeToLive;
    UCHAR  Protocol;            // Protocol of the next layer (e.g., 6 for TCP, 17 for UDP)
    USHORT HeaderChecksum;
    ULONG  SourceAddress;       // Source IP address
    ULONG  DestinationAddress;  // Destination IP address
    // Options and padding can follow here...
} IPV4_HEADER, * PIPV4_HEADER;


//================================================================================
// Layer 4: TCP Header
//================================================================================
typedef struct _TCP_HEADER {
    USHORT SourcePort;
    USHORT DestinationPort;
    ULONG  SequenceNumber;
    ULONG  AcknowledgmentNumber;
    UCHAR  Reserved : 4;        // Reserved bits
    UCHAR  DataOffset : 4;      // Length of the header in 32-bit words
    UCHAR  Flags;               // TCP Flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
    USHORT WindowSize;
    USHORT Checksum;
    USHORT UrgentPointer;
    // Options and padding can follow here...
} TCP_HEADER, * PTCP_HEADER;

// TCP Flags Masks for convenience
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20


//================================================================================
// Layer 4: UDP Header
//================================================================================
typedef struct _UDP_HEADER {
    USHORT SourcePort;
    USHORT DestinationPort;
    USHORT Length;              // Length of UDP header and data in bytes
    USHORT Checksum;
} UDP_HEADER, * PUDP_HEADER;


// 패딩 설정 원복
#pragma pack(pop)


#endif