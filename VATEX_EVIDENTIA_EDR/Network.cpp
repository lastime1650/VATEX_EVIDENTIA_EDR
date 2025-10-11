#include "Network.hpp"
#include "LogSender.hpp"

NTSTATUS NotifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER3* filter
);

void NTAPI FlowDeleteFn(
	_In_ UINT16 layerId,
	_In_ UINT32 calloutId,
	_In_ UINT64 flowContext
);

HANDLE EngineHandle = 0;

GUID g_providerKey = { 0 };
constexpr ULONG NUM_LAYERS = 2; // 필터링할 레이어 개수
UINT32 g_wpsCalloutIds[NUM_LAYERS] = { 0 };
UINT32 g_wpmCalloutIds[NUM_LAYERS] = { 0 };
UINT64 g_wpmFilterIds[NUM_LAYERS] = { 0 };

// Heavy
BOOLEAN Copy_Packet_Data(
	void* layerData,

	UCHAR* outBuffer,
	ULONG bufferSize,

	ULONG* actualSize,
	ULONG* ProtocolNumber
);


NTSTATUS NDIS_PacketFilter_Register(PDEVICE_OBJECT DeviceObject);
NTSTATUS GenerateGUID(_Inout_ GUID* inout_guid);
void MacToString(UCHAR mac[ETHERNET_ADDRESS_LENGTH], CHAR outStr[18]); // 17 + NULL
NTSTATUS StringToMac(
	const CHAR* strMac,   // "00-11-22-33-44-55"
	UCHAR mac[ETHERNET_ADDRESS_LENGTH]
);
NTSTATUS StringToInAddr(
	_In_ CHAR* strIP,
	_Out_ IN_ADDR* outAddr
);


namespace EDR
{
	namespace WFP_Filter
	{
		namespace helper
		{
			BOOLEAN Get_Packet_Size(_In_ void* layerData, _In_ BOOLEAN isInbound, PPARSED_PACKET_INFO* Output)
			{
				if (!Output || !layerData)
					return FALSE;
				/*
				FWPS_PACKET_LIST_INFORMATION0 packetInfo = { 0 };
				if( !NT_SUCCESS( FwpsGetPacketListSecurityInformation0(
					(NET_BUFFER_LIST*)layerData,
					(isInbound ? FWPS_PACKET_LIST_INFORMATION_QUERY_ALL_INBOUND : FWPS_PACKET_LIST_INFORMATION_QUERY_ALL_OUTBOUND),
					&packetInfo
				) ) )
					return FALSE;
					*/
				// 직접 바이트 체크
				NET_BUFFER_LIST* netBufferList = (NET_BUFFER_LIST*)layerData;
				NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
				if (!netBuffer) {
					return FALSE;
				}

				// 1. 이더넷 -> 끝 Layer 까지 길이 구하기
				ULONG frameSize = 0; // 패킷 전체 사이즈
				NET_BUFFER* currentNetBuffer = netBuffer;
				while (currentNetBuffer != NULL) {
					frameSize += NET_BUFFER_DATA_LENGTH(currentNetBuffer);
					currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
				}

				if (frameSize == 0) {
					return FALSE;
				}

				// 2. 패킷 바이너리 할당

				// 패킷 바이너리 정보 메타데이터 할당
				*Output = (PPARSED_PACKET_INFO)ExAllocatePool2(
					POOL_FLAG_NON_PAGED,
					sizeof(PARSED_PACKET_INFO),
					NetworkFilter_ALLOC_TAG
				);
				if (!*Output) {
					return FALSE;
				}
				RtlZeroMemory(*Output, sizeof(PARSED_PACKET_INFO));
				
				// 실제 패킷 프레임 사이즈 할당
				(*Output)->FrameBuffer = (PUCHAR)ExAllocatePool2(
					POOL_FLAG_NON_PAGED,
					frameSize,
					NetworkFilter_ALLOC_TAG
				);
				if (!(*Output)->FrameBuffer)
				{
					ExFreePoolWithTag(*Output, NetworkFilter_ALLOC_TAG);
					return FALSE;
				}

				ULONG bytesCopied = 0;
				currentNetBuffer = netBuffer;
				while (currentNetBuffer != NULL) {
					ULONG len = NET_BUFFER_DATA_LENGTH(currentNetBuffer);
					if (bytesCopied + len > frameSize) {
						// 계산된 크기와 실제 복사 크기가 다른 경우. 오류 상황.
						Release_Parsed_Packet(*Output);
						*Output = NULL;
						return FALSE;
					}

					PUCHAR dataPtr = (PUCHAR)NdisGetDataBuffer(currentNetBuffer, len, NULL, 1, 0);
					if (dataPtr) {
						RtlCopyMemory((*Output)->FrameBuffer + bytesCopied, dataPtr, len);
						bytesCopied += len;
					}
					else {
						// NdisGetDataBuffer가 NULL을 반환하는 경우는 매우 드물며,
						// 이런 경우 MDL 체인을 직접 순회해야 함.
						// 여기서는 간략화를 위해 실패로 처리.
						Release_Parsed_Packet(*Output);
						*Output = NULL;
						return FALSE;
					}
					currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
				}

				// 3. Output 정보 세팅 + 구조체 파싱
				
				PETHERNET_HEADER pEthHeader = NULL;
				PIPV4_HEADER pIpHeader = NULL;


				// 이더넷 계층 검증
				if (frameSize < sizeof(ETHERNET_HEADER)) {
					// 이더넷 헤더보다 작으면 파싱 불가.
					Release_Parsed_Packet(*Output);
					*Output = NULL;
					return FALSE;
				}
				pEthHeader = (PETHERNET_HEADER)(*Output)->FrameBuffer;
				if (RtlUshortByteSwap(pEthHeader->EtherType) != ETHERTYPE_IPV4) {
					Release_Parsed_Packet(*Output);
					*Output = NULL;
					return FALSE; // IPv4 및 해당 계층이상이 아니면 파싱 실패 ( 이더넷 패킷 혼자는 아직 지원 X )
				}
				
				/*
					MAC주소 추출
				*/
				MacToString(
					pEthHeader->SourceAddress,
					(*Output)->ethernet_layer.SourceAddress
				);
				MacToString(
					pEthHeader->DestinationAddress,
					(*Output)->ethernet_layer.DestinationAddress
				);


				(*Output)->network_layer.IsIPv4 = TRUE;

				// 네트워크 계층 검증
				PUCHAR transportHeaderPtr = NULL; // 프로토콜 해석안된 전송계층 시작 주소 (임시형)
				ULONG ipHeaderLength = 0; // 얻은 IP헤더
				if ((*Output)->network_layer.IsIPv4)
				{
					// IPV4

					pIpHeader = (PIPV4_HEADER)((*Output)->FrameBuffer + sizeof(ETHERNET_HEADER));
					ipHeaderLength = pIpHeader->HeaderLength * 4;

					if (frameSize < sizeof(ETHERNET_HEADER) + ipHeaderLength) {
						Release_Parsed_Packet(*Output);
						*Output = NULL;
						return FALSE; // IP 헤더 길이 부족
					}

					// 방향 + IP 복사 (변환 작업 후)
					IN_ADDR addr;
					if (isInbound) {

						addr.S_un.S_addr = (pIpHeader->SourceAddress);
						RtlIpv4AddressToStringA(&addr, (*Output)->network_layer.LocalIp);

						addr.S_un.S_addr = (pIpHeader->DestinationAddress);
						RtlIpv4AddressToStringA(&addr, (*Output)->network_layer.RemoteIp);
					}
					else {

						addr.S_un.S_addr = (pIpHeader->SourceAddress);
						RtlIpv4AddressToStringA(&addr, (*Output)->network_layer.LocalIp);

						addr.S_un.S_addr = (pIpHeader->DestinationAddress);
						RtlIpv4AddressToStringA(&addr, (*Output)->network_layer.RemoteIp);
					}

					transportHeaderPtr = ((PUCHAR)pIpHeader) + ipHeaderLength;

				}
				else
				{
					// IPV6
				}


				(*Output)->network_layer.ProtocolNumber = pIpHeader->Protocol;
				(*Output)->FrameSize = frameSize;

				
				if ((*Output)->network_layer.ProtocolNumber == IP_PROTOCOL_TCP) {
					if (frameSize < sizeof(ETHERNET_HEADER) + ipHeaderLength + sizeof(TCP_HEADER)) 
						return TRUE;

					PTCP_HEADER pTcpHeader = (PTCP_HEADER)transportHeaderPtr;
					(*Output)->transport_layer.IsTCP = TRUE; // TCP

					if (isInbound) {
						(*Output)->transport_layer.LocalPort = RtlUshortByteSwap(pTcpHeader->DestinationPort);
						(*Output)->transport_layer.RemotePort = RtlUshortByteSwap(pTcpHeader->SourcePort);
					}
					else {
						(*Output)->transport_layer.LocalPort = RtlUshortByteSwap(pTcpHeader->SourcePort);
						(*Output)->transport_layer.RemotePort = RtlUshortByteSwap(pTcpHeader->DestinationPort);
					}
				}
				else if ((*Output)->network_layer.ProtocolNumber == IP_PROTOCOL_UDP) {
					if (frameSize < sizeof(ETHERNET_HEADER) + ipHeaderLength + sizeof(UDP_HEADER)) 
						return TRUE;

					(*Output)->transport_layer.IsTCP = FALSE; // UDP

					PUDP_HEADER pUdpHeader = (PUDP_HEADER)transportHeaderPtr;
					if (isInbound) {
						(*Output)->transport_layer.LocalPort = RtlUshortByteSwap(pUdpHeader->DestinationPort);
						(*Output)->transport_layer.RemotePort = RtlUshortByteSwap(pUdpHeader->SourcePort);
					}
					else {
						(*Output)->transport_layer.LocalPort = RtlUshortByteSwap(pUdpHeader->SourcePort);
						(*Output)->transport_layer.RemotePort = RtlUshortByteSwap(pUdpHeader->DestinationPort);
					}
				}
				


				
				return TRUE;
			}

			VOID Release_Parsed_Packet(_In_ PPARSED_PACKET_INFO packetInfo)
			{
				if (packetInfo)
				{
					if(packetInfo->FrameBuffer)
						ExFreePoolWithTag(packetInfo->FrameBuffer, NetworkFilter_ALLOC_TAG);

					ExFreePoolWithTag(packetInfo, NetworkFilter_ALLOC_TAG);
				}
			}
		}
		namespace Handler
		{
			//#define PACKETBUFFALLOC 'PKBF'
			#define PACKETBUFFMAXIMUMSIZE 9216 // MTU (15xx + VLAN TAG + JumboFrame.. )
			extern "C" void FwpsCalloutClassifyFn3(
				_In_ const FWPS_INCOMING_VALUES0* inFixedValues,
				_In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
				_Inout_opt_ void* layerData,
				_In_opt_ const void* classifyContext,
				_In_ const FWPS_FILTER3* filter,
				_In_ UINT64 flowContext,
				_Inout_ FWPS_CLASSIFY_OUT0* classifyOut
			){
				// DISPATCH 레벨 수준
				//UNREFERENCED_PARAMETER(inFixedValues);
				//UNREFERENCED_PARAMETER(inMetaValues);
				//UNREFERENCED_PARAMETER(layerData);
				UNREFERENCED_PARAMETER(classifyContext);
				UNREFERENCED_PARAMETER(filter);
				UNREFERENCED_PARAMETER(flowContext);

				ULONG64 NanoTimestamp = EDR::Util::Timestamp::Get_LocalTimestamp_Nano();

				HANDLE PID = PsGetCurrentProcessId();
				if (PsIsSystemProcess(PsGetCurrentProcess()))
					return;
				if (PID == EDR::Util::Shared::USER_AGENT::ProcessId)
					return;



				// interfac e
				ULONG32 NetworkInterfaceIndex = 0;


				BOOLEAN is_inbound = FALSE;

				switch (inFixedValues->layerId) {
				case FWPS_LAYER_INBOUND_MAC_FRAME_NATIVE:
				{
					is_inbound = TRUE;
					break;
				}
				case FWPS_LAYER_OUTBOUND_MAC_FRAME_NATIVE:
				{
					is_inbound = FALSE;
					break;
				}
					/*
					* 
					* 패킷을 가져오는 오프셋이 IP 또는 UDP을 넘으면 온전한 패킷버퍼를 얻는 것이 불가능함. ( 해당 레이어에서부터 바이트를 얻기 때문 )
					* 이 경우 MAC_FRAME 레이어단에서 직접 구조체로 파싱하면서 처리하는 것으로 결정한다.
					* 
				case FWPS_LAYER_INBOUND_TRANSPORT_V4:
				{

					is_inbound = TRUE;
					//protocolNumber = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
					localIp = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
					localPort = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
					remoteIp = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
					remotePort = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
					break;
				}
				case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
				{
					is_inbound = FALSE;
					//protocolNumber = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
					localIp = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
					localPort = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
					remoteIp = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
					remotePort = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
					break;
				}
				case FWPS_LAYER_INBOUND_IPPACKET_V4:
				{
					
					is_inbound = TRUE;
					localIp = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_IP_LOCAL_ADDRESS].value.uint32;
					remoteIp = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_IP_REMOTE_ADDRESS].value.uint32;
					localPort = 0;
					remotePort = 0;
					break;
				}
				case FWPS_LAYER_OUTBOUND_IPPACKET_V4:
				{
					is_inbound = FALSE;
					localIp = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_IP_LOCAL_ADDRESS].value.uint32;
					remoteIp = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_IP_REMOTE_ADDRESS].value.uint32;
					localPort = 0;
					remotePort = 0;
					break;
				}*/
				default:
				{
					return;
				}
				}
				
				

				helper::PPARSED_PACKET_INFO PACKET_INFO = NULL;
				if (!helper::Get_Packet_Size(
					layerData,
					is_inbound,

					&PACKET_INFO
				))
				{
					// 실패
					return;
				}
				if (is_inbound)
				{
					NetworkInterfaceIndex = inMetaValues->destinationInterfaceIndex;
				}
				else
				{
					NetworkInterfaceIndex = inMetaValues->sourceInterfaceIndex;
				}
				
				// 준비된 모든 정보를 사용하여 유저 모드로 로그를 전송합니다.
				EDR::LogSender::function::NetworkLog(
					PID,
					NanoTimestamp,

					(PUCHAR)PACKET_INFO->ethernet_layer.SourceAddress,
					(PUCHAR)PACKET_INFO->ethernet_layer.DestinationAddress,

					PACKET_INFO->network_layer.ProtocolNumber,

					is_inbound,

					PACKET_INFO->FrameSize,

					(PUCHAR)PACKET_INFO->network_layer.LocalIp,
					(ULONG32)strlen(PACKET_INFO->network_layer.LocalIp),
					PACKET_INFO->transport_layer.LocalPort,
					
					(PUCHAR)PACKET_INFO->network_layer.RemoteIp,
					(ULONG32)strlen(PACKET_INFO->network_layer.RemoteIp),
					PACKET_INFO->transport_layer.RemotePort,

					NetworkInterfaceIndex,
					PACKET_INFO->FrameBuffer
				);

				Release_Parsed_Packet(PACKET_INFO);

				return;
			}
		}

		// response
		namespace Response
		{
			LIST_ENTRY NetworkResponseListHeader;
			EX_PUSH_LOCK lock;

			BOOLEAN _append_node(
				ULONG64 INBOUND_FILTER_ID, ULONG64 OUTBOUND_FILTER_ID, ULONG64 end_timestamp,


				PUCHAR Allocated_macValue_p
			)
			{
				auto node = (PNETWORK_RESPONSE_LIST_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(NETWORK_RESPONSE_LIST_NODE), NetworkResponseListAllocTag);
				if (!node)
					return FALSE;

				node->INBOUND_filterid = INBOUND_FILTER_ID;
				node->OUTBOUND_filterid = OUTBOUND_FILTER_ID;
				node->end_timestamp = end_timestamp;

				node->Mac.AllocatedMacArray = Allocated_macValue_p;

				ExAcquirePushLockExclusive(&lock);
				InsertTailList(&NetworkResponseListHeader, &node->Entry);
				ExReleasePushLockExclusive(&lock);
				return TRUE;
			}
			BOOLEAN _remove_response(ULONG64 in_INBOUND_filterid, ULONG64 in_OUTBOUND_filterid)
			{
				ExAcquirePushLockExclusive(&lock);
				LIST_ENTRY* current = NetworkResponseListHeader.Flink;
				for (current; current != &NetworkResponseListHeader; current = current->Flink)
				{
					auto node = CONTAINING_RECORD(current, NETWORK_RESPONSE_LIST_NODE, Entry);
					if (!node)
						continue;



					// 등록된 filter인지? 정확히 match
					if (
						node->INBOUND_filterid == in_INBOUND_filterid &&
						node->OUTBOUND_filterid == in_OUTBOUND_filterid
						)
					{
						RemoveEntryList(&node->Entry);
						// 동적할당된 mac 값
						if (node->Mac.AllocatedMacArray)
							ExFreePoolWithTag(node->Mac.AllocatedMacArray, 'macF');
						ExFreePoolWithTag(node, NetworkResponseListAllocTag);

						ExReleasePushLockExclusive(&lock);
						return TRUE;
					}

				}
				ExReleasePushLockExclusive(&lock);
				return FALSE;
			}

			BOOLEAN MacResponse_Insert(PCHAR MacAddress, ULONG64 end_nanotimestamp)
			{
				ULONG64 INBOUND_FILTER_ID = 0;
				ULONG64 OUTBOUND_FILTER_ID = 0;

				PUCHAR Allocated_macValue = NULL;
				if (!NT_SUCCESS(
						EDR::WFP_Filter::Response::Filter::MAC::Add_Response_net_filter_MAC(
							MacAddress,
							&INBOUND_FILTER_ID,
							&OUTBOUND_FILTER_ID,

							&Allocated_macValue
						)
					)
				)
				{
					return FALSE;
				}

				return _append_node(
					INBOUND_FILTER_ID,
					OUTBOUND_FILTER_ID,
					end_nanotimestamp,
					Allocated_macValue
				);
			}
			BOOLEAN OnlyIPResponse_Insert(PCHAR RemoteIpAddress, ULONG64 end_nanotimestamp)
			{
				ULONG64 INBOUND_FILTER_ID = 0;
				ULONG64 OUTBOUND_FILTER_ID = 0;

				if (!NT_SUCCESS(
					EDR::WFP_Filter::Response::Filter::IP::Add_Response_net_filter_IP(
						RemoteIpAddress,
						&INBOUND_FILTER_ID,
						&OUTBOUND_FILTER_ID
					)
				)
					)
				{
					return FALSE;
				}

				return _append_node(
					INBOUND_FILTER_ID,
					OUTBOUND_FILTER_ID,
					end_nanotimestamp,
					NULL
				);
			}
			BOOLEAN IPwithPORTResponse_Insert(PCHAR RemoteIpAddress, ULONG32 port, ULONG64 end_nanotimestamp)
			{
				ULONG64 INBOUND_FILTER_ID = 0;
				ULONG64 OUTBOUND_FILTER_ID = 0;

				if (!NT_SUCCESS(
						EDR::WFP_Filter::Response::Filter::IPwithPORT::Add_Response_net_filter_IPwithPORT(
							RemoteIpAddress,
							port,
							&INBOUND_FILTER_ID,
							&OUTBOUND_FILTER_ID
						)
					)
				)
				{
					return FALSE;
				}

				return _append_node(
					INBOUND_FILTER_ID,
					OUTBOUND_FILTER_ID,
					end_nanotimestamp,
					NULL
				);
			}

			VOID RemoveNetworkResponse(ULONG64 in_INBOUND_filterid, ULONG64 in_OUTBOUND_filterid)
			{
				_remove_response(in_INBOUND_filterid, in_OUTBOUND_filterid);
			}
			



			VOID _NetworkResponse_Initialize()
			{
				ExInitializePushLock(&lock);
				InitializeListHead(&NetworkResponseListHeader);
				HANDLE thread = NULL;
				PsCreateSystemThread(
					&thread,
					THREAD_ALL_ACCESS,
					NULL,
					NULL,
					NULL,
					Loop_Monitor_Network_Response,
					NULL
				);
				if (thread)
					ZwClose(thread);
			}
			VOID _Cleanup_NetworkResponse()
			{
				ExAcquirePushLockExclusive(&lock);
				LIST_ENTRY* current = NetworkResponseListHeader.Flink;
				while (current != &NetworkResponseListHeader)
				{
					auto node = CONTAINING_RECORD(current, NETWORK_RESPONSE_LIST_NODE, Entry);
					LIST_ENTRY* next = current->Flink; // 다음 노드를 미리 저장

					ULONG64 current_nanotimestamp = EDR::Util::Timestamp::Get_LocalTimestamp_Nano();

					EDR::WFP_Filter::Response::Filter::Remove_Response_filter(node->INBOUND_filterid);
					EDR::WFP_Filter::Response::Filter::Remove_Response_filter(node->OUTBOUND_filterid);

					RemoveEntryList(&node->Entry);

					if (node->Mac.AllocatedMacArray)
						ExFreePoolWithTag(node->Mac.AllocatedMacArray, 'macF');

					ExFreePoolWithTag(node, NetworkResponseListAllocTag);

					current = next; // 미리 저장해둔 다음 노드로 이동
				}
				ExReleasePushLockExclusive(&lock);
			}
			VOID Loop_Monitor_Network_Response(PVOID ctx)
			{
				UNREFERENCED_PARAMETER(ctx);
				LARGE_INTEGER interval;
				interval.QuadPart = -5LL * 10 * 1000 * 1000; // 5초

				while (true)
				{
					ExAcquirePushLockExclusive(&lock);
					LIST_ENTRY* current = NetworkResponseListHeader.Flink;
					while (current != &NetworkResponseListHeader)
					{
						auto node = CONTAINING_RECORD(current, NETWORK_RESPONSE_LIST_NODE, Entry);
						LIST_ENTRY* next = current->Flink; // 다음 노드를 미리 저장

						ULONG64 current_nanotimestamp = EDR::Util::Timestamp::Get_LocalTimestamp_Nano();

						if (current_nanotimestamp >= node->end_timestamp)
						{
							EDR::WFP_Filter::Response::Filter::Remove_Response_filter(node->INBOUND_filterid);
							EDR::WFP_Filter::Response::Filter::Remove_Response_filter(node->OUTBOUND_filterid);

							RemoveEntryList(&node->Entry);

							if (node->Mac.AllocatedMacArray)
								ExFreePoolWithTag(node->Mac.AllocatedMacArray, 'macF');

							ExFreePoolWithTag(node, NetworkResponseListAllocTag);
						}
						current = next; // 미리 저장해둔 다음 노드로 이동
					}
					ExReleasePushLockExclusive(&lock);

					KeDelayExecutionThread(KernelMode, FALSE, &interval);
				}
			}

			namespace Filter
			{
#define BOUND_SIZE 2
#define INBOUND_INDEX 0
#define OUTBOUND_INDEX 1
				namespace MAC
				{
					NTSTATUS Add_Response_net_filter_MAC(
						PCHAR MacAddress, 
						ULONG64* out_inbound_response_filter_id, 
						ULONG64* out_outbound_response_filter_id,

						PUCHAR* out_allocated_mac_uint8_value
					)
					{
						if (!EngineHandle || !MacAddress)
							return STATUS_INVALID_PARAMETER;

						FWPM_FILTER0 filter[BOUND_SIZE];
						FWPM_FILTER_CONDITION0 condition[BOUND_SIZE];

						FWP_BYTE_ARRAY6* macValue = (FWP_BYTE_ARRAY6*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(FWP_BYTE_ARRAY6), 'macF');
						if (!macValue)
							return STATUS_INSUFFICIENT_RESOURCES;

						*out_allocated_mac_uint8_value = (PUCHAR)macValue;

						NTSTATUS st = StringToMac(MacAddress, macValue->byteArray6);
						if (!NT_SUCCESS(st))
						{
							ExFreePoolWithTag(macValue, 'macF');
							return st;
						}

						{
							// [1/2] INBOUND
							filter[INBOUND_INDEX].layerKey = FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET;

							filter[INBOUND_INDEX].displayData.name = (wchar_t*)L"Block_MAC_Filter";
							filter[INBOUND_INDEX].providerKey = &g_providerKey;
							filter[INBOUND_INDEX].action.type = FWP_ACTION_BLOCK;
							filter[INBOUND_INDEX].weight.type = FWP_UINT8;
							filter[INBOUND_INDEX].weight.uint8 = 15;

							condition[INBOUND_INDEX].fieldKey = FWPM_CONDITION_MAC_LOCAL_ADDRESS;

							condition[INBOUND_INDEX].matchType = FWP_MATCH_EQUAL;
							condition[INBOUND_INDEX].conditionValue.type = FWP_BYTE_ARRAY6_TYPE;
							condition[INBOUND_INDEX].conditionValue.byteArray6 = macValue;

							filter[INBOUND_INDEX].numFilterConditions = 1;
							filter[INBOUND_INDEX].filterCondition = &condition[INBOUND_INDEX];
						}
						
						{
							// [2/2] OUTBOUND
							filter[OUTBOUND_INDEX].layerKey = FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET;

							filter[OUTBOUND_INDEX].displayData.name = (wchar_t*)L"Block_MAC_Filter";
							filter[OUTBOUND_INDEX].providerKey = &g_providerKey;
							filter[OUTBOUND_INDEX].action.type = FWP_ACTION_BLOCK;
							filter[OUTBOUND_INDEX].weight.type = FWP_UINT8;
							filter[OUTBOUND_INDEX].weight.uint8 = 15;

							condition[OUTBOUND_INDEX].fieldKey = FWPM_CONDITION_MAC_REMOTE_ADDRESS;

							condition[OUTBOUND_INDEX].matchType = FWP_MATCH_EQUAL;
							condition[OUTBOUND_INDEX].conditionValue.type = FWP_BYTE_ARRAY6_TYPE;
							condition[OUTBOUND_INDEX].conditionValue.byteArray6 = macValue;

							filter[OUTBOUND_INDEX].numFilterConditions = 1;
							filter[OUTBOUND_INDEX].filterCondition = &condition[OUTBOUND_INDEX];
						}

						
						NTSTATUS status; 
						UINT64 INBOUND__filterId = 0;
						UINT64 OUTBOUND__filterId = 0;

						status = FwpmTransactionBegin(EngineHandle, 0);////////////////////////////////////////////////////////
						if (!NT_SUCCESS(status))
						{
							ExFreePoolWithTag(macValue, 'macF');
							return status;
						}

						
						// INBOUND
						status = FwpmFilterAdd(EngineHandle, &filter[INBOUND_INDEX], NULL, &INBOUND__filterId);
						if (!NT_SUCCESS(status) )
						{
							ExFreePoolWithTag(macValue, 'macF');
							FwpmTransactionAbort(EngineHandle);
							return status;
						}
						// OUTBOUND
						status = FwpmFilterAdd(EngineHandle, &filter[OUTBOUND_INDEX], NULL, &OUTBOUND__filterId);
						if (!NT_SUCCESS(status) )
						{
							ExFreePoolWithTag(macValue, 'macF');
							FwpmTransactionAbort(EngineHandle);
							return status;
						}
						status = FwpmTransactionCommit(EngineHandle);////////////////////////////////////////////////////////////

						*out_inbound_response_filter_id = INBOUND__filterId;
						*out_outbound_response_filter_id = OUTBOUND__filterId;

						return status;
					}
				}
				namespace IP
				{
					NTSTATUS Add_Response_net_filter_IP(
						CHAR* in_ip,
						ULONG64* out_inbound_response_filter_id,
						ULONG64* out_outbound_response_filter_id
					)
					{
						if (!EngineHandle || !in_ip)
							return STATUS_INVALID_PARAMETER;

						IN_ADDR target_ip;
						StringToInAddr(in_ip, &target_ip);

						FWPM_FILTER0 filter[BOUND_SIZE];
						FWPM_FILTER_CONDITION0 condition[BOUND_SIZE];

						{
							// INBOUND
							filter[INBOUND_INDEX].layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
							filter[INBOUND_INDEX].displayData.name = (wchar_t*)L"Block_IP_Filter";
							filter[INBOUND_INDEX].providerKey = &g_providerKey;
							filter[INBOUND_INDEX].action.type = FWP_ACTION_BLOCK;
							filter[INBOUND_INDEX].weight.type = FWP_UINT8;
							filter[INBOUND_INDEX].weight.uint8 = 15;

							condition[INBOUND_INDEX].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
							condition[INBOUND_INDEX].matchType = FWP_MATCH_EQUAL;
							condition[INBOUND_INDEX].conditionValue.type = FWP_UINT32;
							condition[INBOUND_INDEX].conditionValue.uint32 = target_ip.S_un.S_addr;

							filter[INBOUND_INDEX].numFilterConditions = 1;
							filter[INBOUND_INDEX].filterCondition = &condition[INBOUND_INDEX];
						}
						
						{
							// OUTBOUND
							filter[OUTBOUND_INDEX].layerKey = FWPM_LAYER_OUTBOUND_IPPACKET_V4;
							filter[OUTBOUND_INDEX].displayData.name = (wchar_t*)L"Block_IP_Filter";
							filter[OUTBOUND_INDEX].providerKey = &g_providerKey;
							filter[OUTBOUND_INDEX].action.type = FWP_ACTION_BLOCK;
							filter[OUTBOUND_INDEX].weight.type = FWP_UINT8;
							filter[OUTBOUND_INDEX].weight.uint8 = 15;

							condition[OUTBOUND_INDEX].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
							condition[OUTBOUND_INDEX].matchType = FWP_MATCH_EQUAL;
							condition[OUTBOUND_INDEX].conditionValue.type = FWP_UINT32;
							condition[OUTBOUND_INDEX].conditionValue.uint32 = target_ip.S_un.S_addr;

							filter[OUTBOUND_INDEX].numFilterConditions = 1;
							filter[OUTBOUND_INDEX].filterCondition = &condition[OUTBOUND_INDEX];
						}
						

						NTSTATUS status;
						UINT64 INBOUND__filterId = 0;
						UINT64 OUTBOUND__filterId = 0;

						status = FwpmTransactionBegin(EngineHandle, 0);
						if (!NT_SUCCESS(status))
							return status;

						status = FwpmFilterAdd(EngineHandle, &filter[INBOUND_INDEX], NULL, &INBOUND__filterId);
						if (!NT_SUCCESS(status))
						{
							FwpmTransactionAbort(EngineHandle);
							return status;
						}

						status = FwpmFilterAdd(EngineHandle, &filter[OUTBOUND_INDEX], NULL, &OUTBOUND__filterId);
						if (!NT_SUCCESS(status))
						{
							FwpmTransactionAbort(EngineHandle);
							return status;
						}

						status = FwpmTransactionCommit(EngineHandle);

						*out_inbound_response_filter_id = INBOUND__filterId;
						*out_outbound_response_filter_id = OUTBOUND__filterId;

						return status;
					}
				}
				namespace IPwithPORT
				{
					NTSTATUS Add_Response_net_filter_IPwithPORT(
						CHAR* in_ip,
						ULONG32 in_port,
						ULONG64* out_inbound_response_filter_id,
						ULONG64* out_outbound_response_filter_id
					)
					{
						if (!EngineHandle || !in_ip)
							return STATUS_INVALID_PARAMETER;

						IN_ADDR target_ip;
						StringToInAddr(in_ip, &target_ip);

						FWPM_FILTER0 filter[BOUND_SIZE];
						FWPM_FILTER_CONDITION0 condition[2 * BOUND_SIZE]; // IP + PORT 두 개 조건

						NTSTATUS status;
						UINT64 INBOUND__filterId = 0;
						UINT64 OUTBOUND__filterId = 0;

						{
							// INBOUND
							filter[INBOUND_INDEX].layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
							filter[INBOUND_INDEX].displayData.name = (wchar_t*)L"Block_IPPort_Filter";
							filter[INBOUND_INDEX].providerKey = &g_providerKey;
							filter[INBOUND_INDEX].action.type = FWP_ACTION_BLOCK;
							filter[INBOUND_INDEX].weight.type = FWP_UINT8;
							filter[INBOUND_INDEX].weight.uint8 = 15;

							// IP 조건
							condition[INBOUND_INDEX * 2].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
							condition[INBOUND_INDEX * 2].matchType = FWP_MATCH_EQUAL;
							condition[INBOUND_INDEX * 2].conditionValue.type = FWP_UINT32;
							condition[INBOUND_INDEX * 2].conditionValue.uint32 = target_ip.S_un.S_addr;

							// PORT 조건
							condition[INBOUND_INDEX * 2 + 1].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
							condition[INBOUND_INDEX * 2 + 1].matchType = FWP_MATCH_EQUAL;
							condition[INBOUND_INDEX * 2 + 1].conditionValue.type = FWP_UINT16;
							condition[INBOUND_INDEX * 2 + 1].conditionValue.uint16 = RtlUshortByteSwap((UINT16)in_port);

							filter[INBOUND_INDEX].numFilterConditions = 2;
							filter[INBOUND_INDEX].filterCondition = &condition[INBOUND_INDEX * 2];
						}

						{
							// OUTBOUND
							filter[OUTBOUND_INDEX].layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
							filter[OUTBOUND_INDEX].displayData.name = (wchar_t*)L"Block_IPPort_Filter";
							filter[OUTBOUND_INDEX].providerKey = &g_providerKey;
							filter[OUTBOUND_INDEX].action.type = FWP_ACTION_BLOCK;
							filter[OUTBOUND_INDEX].weight.type = FWP_UINT8;
							filter[OUTBOUND_INDEX].weight.uint8 = 15;

							// IP 조건
							condition[OUTBOUND_INDEX * 2].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
							condition[OUTBOUND_INDEX * 2].matchType = FWP_MATCH_EQUAL;
							condition[OUTBOUND_INDEX * 2].conditionValue.type = FWP_UINT32;
							condition[OUTBOUND_INDEX * 2].conditionValue.uint32 = target_ip.S_un.S_addr;

							// PORT 조건
							condition[OUTBOUND_INDEX * 2 + 1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
							condition[OUTBOUND_INDEX * 2 + 1].matchType = FWP_MATCH_EQUAL;
							condition[OUTBOUND_INDEX * 2 + 1].conditionValue.type = FWP_UINT16;
							condition[OUTBOUND_INDEX * 2 + 1].conditionValue.uint16 = RtlUshortByteSwap((UINT16)in_port);

							filter[OUTBOUND_INDEX].numFilterConditions = 2;
							filter[OUTBOUND_INDEX].filterCondition = &condition[OUTBOUND_INDEX * 2];
						}
						

						// 트랜잭션
						status = FwpmTransactionBegin(EngineHandle, 0);
						if (!NT_SUCCESS(status))
							return status;

						status = FwpmFilterAdd(EngineHandle, &filter[INBOUND_INDEX], NULL, &INBOUND__filterId);
						if (!NT_SUCCESS(status))
						{
							FwpmTransactionAbort(EngineHandle);
							return status;
						}

						status = FwpmFilterAdd(EngineHandle, &filter[OUTBOUND_INDEX], NULL, &OUTBOUND__filterId);
						if (!NT_SUCCESS(status))
						{
							FwpmTransactionAbort(EngineHandle);
							return status;
						}

						status = FwpmTransactionCommit(EngineHandle);

						*out_inbound_response_filter_id = INBOUND__filterId;
						*out_outbound_response_filter_id = OUTBOUND__filterId;

						return status;
					}
				}

				NTSTATUS Remove_Response_filter(
					_In_ ULONG64 filterId
				)
				{
					return FwpmFilterDeleteById(EngineHandle, filterId);
				}
			}
		}

		NTSTATUS Load_WFP_Filter(PDEVICE_OBJECT DeviceObject)
		{
			return NDIS_PacketFilter_Register(DeviceObject);
		}

		VOID Cleanup_WFP_Filter()
		{
			// 엔진 핸들이 유효하지 않으면 정리할 것이 없음
			if (EngineHandle == NULL)
			{
				return;
			}

			// 1. 필터 및 콜아웃 제거 (등록의 역순)
			for (ULONG32 i = 0; i < NUM_LAYERS; i++)
			{
				// FwpmFilter 제거
				if (g_wpmFilterIds[i] != 0)
				{
					FwpmFilterDeleteById(EngineHandle, g_wpmFilterIds[i]);
					g_wpmFilterIds[i] = 0; // 재진입 방지
				}

				// FwpmCallout 제거
				if (g_wpmCalloutIds[i] != 0)
				{
					FwpmCalloutDeleteById(EngineHandle, g_wpmCalloutIds[i]);
					g_wpmCalloutIds[i] = 0; // 재진입 방지
				}

				// FwpsCallout 등록 취소
				if (g_wpsCalloutIds[i] != 0)
				{
					FwpsCalloutUnregisterById(g_wpsCalloutIds[i]);
					g_wpsCalloutIds[i] = 0; // 재진입 방지
				}
			}

			// 2. 제공자(Provider) 제거
			// providerKey가 유효한 경우에만 시도
			if (RtlZeroMemory(&g_providerKey, sizeof(GUID)))
			{
				// 제공자를 제거하면 관련된 모든 필터와 콜아웃이 자동으로 제거되지만,
				// 명시적으로 하나씩 제거하는 것이 더 안전하고 깔끔합니다.
				FwpmProviderDeleteByKey(EngineHandle, &g_providerKey);
			}

			// 3.차단 풀 제거
			EDR::WFP_Filter::Response::_Cleanup_NetworkResponse();

			// 4. 필터 엔진 핸들 닫기
			FwpmEngineClose(EngineHandle);
			EngineHandle = NULL; // 핸들을 NULL로 설정하여 중복 해제 방지
		}
	}
}



BOOLEAN Copy_Packet_Data(
	void* layerData,
	UCHAR* outBuffer,
	ULONG bufferSize,
	ULONG* actualSize,
	ULONG* ProtocolNumber
) {
	if (!layerData || !outBuffer || !actualSize || !ProtocolNumber)
		return FALSE;

	*actualSize = 0;
	*ProtocolNumber = 0;

	NET_BUFFER_LIST* netBufferList = (NET_BUFFER_LIST*)layerData;
	if (!netBufferList)
		return FALSE;

	NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
	while (netBuffer) {
		ULONG len = NET_BUFFER_DATA_LENGTH(netBuffer);
		if (*actualSize + len > bufferSize) {
			len = bufferSize - *actualSize; // 남은 공간만 복사
		}

		UCHAR* dataPtr = (UCHAR*)NdisGetDataBuffer(netBuffer, len, NULL, 1, 0);
		if (dataPtr) {
			RtlCopyMemory(outBuffer + *actualSize, dataPtr, len);
			*actualSize += len;
		}

		// 첫 번째 NET_BUFFER에서 프로토콜 번호 추출
		if (*ProtocolNumber == 0 && len >= sizeof(IPV4_HEADER)) {
			PIPV4_HEADER ipHeader = (PIPV4_HEADER)outBuffer;
			*ProtocolNumber = ipHeader->Protocol;
		}

		netBuffer = NET_BUFFER_NEXT_NB(netBuffer);
	}

	return TRUE;
}

/*
* 
* 
* 더 이상 사용하지 않음 ( Old ) 
BOOLEAN Get_Packet_Size(void* layerData, ULONG32* PacketSize, ULONG32* ProtocolNumber) {

	// PAGED_CODE(); // CalloutFn은 DISPATCH_LEVEL에서 실행될 수 있으므로 PAGED_CODE 주석 처리 또는 제거

	if (!layerData || !PacketSize || !ProtocolNumber) {
		return FALSE; // 유효하지 않은 인자
	}

	*PacketSize = 0;
	*ProtocolNumber = 0; // 기본값 초기화

	NET_BUFFER_LIST* netBufferList = (NET_BUFFER_LIST*)layerData;
	if (netBufferList == NULL) {
		return FALSE;
	}

	NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);

	if (netBuffer != NULL) {
		// 첫 번째 NET_BUFFER에서 IP 헤더 정보를 추출 시도
		ULONG packetDataLength = NET_BUFFER_DATA_LENGTH(netBuffer);
		UCHAR* packetData = (UCHAR * )NdisGetDataBuffer(netBuffer, packetDataLength, NULL, 1, 0);

		if (packetData != NULL && packetDataLength >= sizeof(IPV4_HEADER)) {
			// IPv4 헤더 캐스팅
			PIPV4_HEADER ipHeader = (PIPV4_HEADER)packetData;

			// IP 프로토콜 번호 추출
			*ProtocolNumber = ipHeader->Protocol;
		}

		// 전체 패킷 사이즈 계산
		NET_BUFFER* currentNetBuffer = netBuffer; // 첫 번째 NET_BUFFER부터 시작
		while (currentNetBuffer != NULL) {
			*PacketSize += NET_BUFFER_DATA_LENGTH(currentNetBuffer);
			currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
		}
	}
	else {
		return FALSE; // NET_BUFFER가 없는 경우
	}

	return TRUE;
}
*/

NTSTATUS Set_CallOut(
	PDEVICE_OBJECT DeviceObject,

	GUID* ProviderKey,

	const GUID LayerKey,

	UINT32* WPS_CalloutId,
	UINT32* WPM_CalloutId,
	UINT64* WPM_Filterid
) {
	if (!DeviceObject || !ProviderKey || !WPS_CalloutId || !WPM_CalloutId || !WPM_Filterid)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status;

	// 수정모드 진입 ( 트랜잭션 진입 ) 
	status = FwpmTransactionBegin(EngineHandle, 0);
	if (status != STATUS_SUCCESS) {
		return status;
	}






	/* ===================필터 엔진 생성============= */

	/* Fwps */
	// 동적 key 생성 ( 이는 콜아웃 키 반환 )
	GUID Calloutkey = { 0, };
	status = GenerateGUID(&Calloutkey);

	FWPS_CALLOUT3 callout = { 0, };
	callout.calloutKey = Calloutkey; // Fwpm 등록시 참조되는 키임

	callout.flags = 0;
	callout.classifyFn = EDR::WFP_Filter::Handler::FwpsCalloutClassifyFn3;
	callout.notifyFn = NotifyFn;
	callout.flowDeleteFn = FlowDeleteFn;

	// Fwps 콜아웃 등록 ( 기능 등록 )
	status = FwpsCalloutRegister3(DeviceObject, &callout, WPS_CalloutId);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	/* Fwpm */
	// wpm콜아웃 등록 ( 정책 등록 ) 
	FWPM_CALLOUT0 pm_callout = { 0, };
	pm_callout.calloutKey = Calloutkey;
	pm_callout.displayData.name = (wchar_t*)L"wfpkm_VATEX_callout";;
	pm_callout.displayData.description = (wchar_t*)L"The callout object for wfp-VATEX";;
	pm_callout.providerKey = ProviderKey;
	pm_callout.applicableLayer = LayerKey;

	status = FwpmCalloutAdd(EngineHandle, &pm_callout, NULL, WPM_CalloutId);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	// WPM 필터 등록
	FWPM_FILTER  fwpm_filter = { 0, };
	//fwpm_filter_id
	fwpm_filter.displayData.name = (wchar_t*)L"wfpkm_VATEX_filter";
	fwpm_filter.displayData.description = (wchar_t*)L"The filter object for wfp-VATEX";
	fwpm_filter.layerKey = LayerKey; // 파라미터로 가져온 레이어 필터
	fwpm_filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	fwpm_filter.action.calloutKey = Calloutkey;

	// 가중치가 높으면 가상 먼저 실행됨.
	fwpm_filter.weight.type = FWP_UINT64; // 사용할 필드 설정
	UINT64 weight = 0xffffffffffffffff; // 가중치 설정
	fwpm_filter.weight.uint64 = &weight; // 가중치 설정

	status = FwpmFilterAdd(EngineHandle, &fwpm_filter, NULL, WPM_Filterid);
	if (status != STATUS_SUCCESS) {
		return status;
	}



	// 수정완료
	status = FwpmTransactionCommit(EngineHandle);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	return status;
}


NTSTATUS InitializeFilterEngine(
	GUID* provider_key
) {
	if (!provider_key) return STATUS_INVALID_PARAMETER;
	NTSTATUS status;


	// 엔진 열기
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);
	if (status != STATUS_SUCCESS) {
		return status;
	}


	// 엔진 수정모드 진입 ( 트랜잭션 진입 ) 
	status = FwpmTransactionBegin(EngineHandle, 0);
	if (status != STATUS_SUCCESS) {
		return status;
	}




	// GUID 동적생성
	status = GenerateGUID(provider_key);

	// GUID 키 설정
	FWPM_PROVIDER wfp_provider = { 0, };
	wfp_provider.serviceName = (wchar_t*)L"wfpk";
	wfp_provider.displayData.name = (wchar_t*)L"wfpkm_VATEX_provider";
	wfp_provider.displayData.description = (wchar_t*)L"The provider object for wfp-VATEX";

	wfp_provider.providerKey = *provider_key;

	// 제공자 등록
	status = FwpmProviderAdd(EngineHandle, &wfp_provider, NULL);
	if ((status) != STATUS_SUCCESS) {
		return status;
	}






	// 엔진 수정완료
	status = FwpmTransactionCommit(EngineHandle);
	if ((status) != STATUS_SUCCESS) {
		return status;
	}

	return status;
}

NTSTATUS NDIS_PacketFilter_Register(PDEVICE_OBJECT DeviceObject) {
	if (!DeviceObject) return STATUS_INVALID_PARAMETER;
	NTSTATUS status = STATUS_SUCCESS;

	// GUID provider_key = { 0, }; // 지역 변수 대신 전역 변수 사용
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "엔진 생성 시도\n");
	status = InitializeFilterEngine(&g_providerKey); // 전역 변수에 키 저장
	if (status != STATUS_SUCCESS) {
		return status;
	}

	const GUID LayerKey[] = {
		//FWPM_LAYER_INBOUND_TRANSPORT_V4,
		//FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
		//FWPM_LAYER_INBOUND_IPPACKET_V4,
		//FWPM_LAYER_OUTBOUND_IPPACKET_V4
		FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
		FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE
	};

	// NUM_LAYERS와 배열 크기가 일치하는지 확인
	static_assert(sizeof(LayerKey) / sizeof(GUID) == NUM_LAYERS, "LayerKey array size mismatch with NUM_LAYERS");

	for (ULONG32 i = 0; i < NUM_LAYERS; i++) {
		// 지역 변수 대신 전역 배열에 ID 저장
		status = Set_CallOut(
			DeviceObject,
			&g_providerKey,
			LayerKey[i],
			&g_wpsCalloutIds[i],
			&g_wpmCalloutIds[i],
			&g_wpmFilterIds[i]
		);
		if (status != STATUS_SUCCESS) {
			// 실패 시, 지금까지 등록된 것을 정리해야 하지만 간단하게 하기 위해 바로 반환
			// 더 견고한 코드는 여기서 UnSet_WFP_Filter를 호출하여 부분 정리
			return status;
		}
	}

	// 차단등록
	EDR::WFP_Filter::Response::_NetworkResponse_Initialize();

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "패킷필터 등록 완료\n");
	return status;
}


void MacToString(UCHAR mac[ETHERNET_ADDRESS_LENGTH], CHAR outStr[18]) // 17 + NULL
{
	RtlStringCchPrintfA(
		(NTSTRSAFE_PSTR)outStr,
		18,
		"%02X-%02X-%02X-%02X-%02X-%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
	);
}

NTSTATUS StringToInAddr(
	_In_ CHAR* strIP,
	_Out_ IN_ADDR* outAddr
)
{
	if (!strIP || !outAddr)
		return STATUS_INVALID_PARAMETER;

	PCSTR terminator = NULL;
	NTSTATUS status = RtlIpv4StringToAddressA(strIP, TRUE, &terminator, outAddr);
	if (!NT_SUCCESS(status) )  // RtlIpv4StringToAddressA는 LONG 반환
		return STATUS_INVALID_PARAMETER;

	return STATUS_SUCCESS;
}

NTSTATUS StringToMac(
	const CHAR* strMac,   // "00-11-22-33-44-55"
	UCHAR mac[ETHERNET_ADDRESS_LENGTH]
)
{
	if (!strMac || !mac)
		return STATUS_INVALID_PARAMETER;

	for (int i = 0; i < ETHERNET_ADDRESS_LENGTH; i++)
	{
		ULONG value = 0;
		NTSTATUS status = RtlCharToInteger(strMac, 16, &value);
		if (!NT_SUCCESS(status))
			return status;

		mac[i] = (UCHAR)value;

		// 다음 옥텟으로 이동 ("-" 스킵)
		strMac += 2;
		if (i < ETHERNET_ADDRESS_LENGTH - 1)
		{
			if (*strMac != '-')
				return STATUS_INVALID_PARAMETER;
			strMac++;
		}
	}
	return STATUS_SUCCESS;
}


/*
	사용안함@@@@@@@@@@@@@@@@@@@@
*/
NTSTATUS NotifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER3* filter
) {
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "NotifyFn\n");
	return STATUS_SUCCESS;
}

void NTAPI FlowDeleteFn(
	_In_ UINT16 layerId,
	_In_ UINT32 calloutId,
	_In_ UINT64 flowContext
) {
	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UNREFERENCED_PARAMETER(flowContext);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FlowDeleteFn\n");
	return;
}

NTSTATUS GenerateGUID(_Inout_ GUID* inout_guid) {
	if (!inout_guid) return STATUS_INVALID_PARAMETER;

	NTSTATUS status;

	do {
		status = ExUuidCreate(inout_guid);
		if (status == STATUS_SUCCESS) {
			return STATUS_SUCCESS;
		}
	} while (status == STATUS_RETRY);

	if (status == RPC_NT_UUID_LOCAL_ONLY) {
		debug_log("Warning: Local-only UUID generated\n");
		return STATUS_SUCCESS;  // 경고를 출력하지만 계속 진행
	}

	debug_log("Failed to generate UUID, status: %x\n", status);
	return status;
}