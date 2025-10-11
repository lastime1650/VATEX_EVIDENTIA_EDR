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
constexpr ULONG NUM_LAYERS = 2; // ���͸��� ���̾� ����
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
				// ���� ����Ʈ üũ
				NET_BUFFER_LIST* netBufferList = (NET_BUFFER_LIST*)layerData;
				NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
				if (!netBuffer) {
					return FALSE;
				}

				// 1. �̴��� -> �� Layer ���� ���� ���ϱ�
				ULONG frameSize = 0; // ��Ŷ ��ü ������
				NET_BUFFER* currentNetBuffer = netBuffer;
				while (currentNetBuffer != NULL) {
					frameSize += NET_BUFFER_DATA_LENGTH(currentNetBuffer);
					currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
				}

				if (frameSize == 0) {
					return FALSE;
				}

				// 2. ��Ŷ ���̳ʸ� �Ҵ�

				// ��Ŷ ���̳ʸ� ���� ��Ÿ������ �Ҵ�
				*Output = (PPARSED_PACKET_INFO)ExAllocatePool2(
					POOL_FLAG_NON_PAGED,
					sizeof(PARSED_PACKET_INFO),
					NetworkFilter_ALLOC_TAG
				);
				if (!*Output) {
					return FALSE;
				}
				RtlZeroMemory(*Output, sizeof(PARSED_PACKET_INFO));
				
				// ���� ��Ŷ ������ ������ �Ҵ�
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
						// ���� ũ��� ���� ���� ũ�Ⱑ �ٸ� ���. ���� ��Ȳ.
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
						// NdisGetDataBuffer�� NULL�� ��ȯ�ϴ� ���� �ſ� �幰��,
						// �̷� ��� MDL ü���� ���� ��ȸ�ؾ� ��.
						// ���⼭�� ����ȭ�� ���� ���з� ó��.
						Release_Parsed_Packet(*Output);
						*Output = NULL;
						return FALSE;
					}
					currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
				}

				// 3. Output ���� ���� + ����ü �Ľ�
				
				PETHERNET_HEADER pEthHeader = NULL;
				PIPV4_HEADER pIpHeader = NULL;


				// �̴��� ���� ����
				if (frameSize < sizeof(ETHERNET_HEADER)) {
					// �̴��� ������� ������ �Ľ� �Ұ�.
					Release_Parsed_Packet(*Output);
					*Output = NULL;
					return FALSE;
				}
				pEthHeader = (PETHERNET_HEADER)(*Output)->FrameBuffer;
				if (RtlUshortByteSwap(pEthHeader->EtherType) != ETHERTYPE_IPV4) {
					Release_Parsed_Packet(*Output);
					*Output = NULL;
					return FALSE; // IPv4 �� �ش� �����̻��� �ƴϸ� �Ľ� ���� ( �̴��� ��Ŷ ȥ�ڴ� ���� ���� X )
				}
				
				/*
					MAC�ּ� ����
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

				// ��Ʈ��ũ ���� ����
				PUCHAR transportHeaderPtr = NULL; // �������� �ؼ��ȵ� ���۰��� ���� �ּ� (�ӽ���)
				ULONG ipHeaderLength = 0; // ���� IP���
				if ((*Output)->network_layer.IsIPv4)
				{
					// IPV4

					pIpHeader = (PIPV4_HEADER)((*Output)->FrameBuffer + sizeof(ETHERNET_HEADER));
					ipHeaderLength = pIpHeader->HeaderLength * 4;

					if (frameSize < sizeof(ETHERNET_HEADER) + ipHeaderLength) {
						Release_Parsed_Packet(*Output);
						*Output = NULL;
						return FALSE; // IP ��� ���� ����
					}

					// ���� + IP ���� (��ȯ �۾� ��)
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
				// DISPATCH ���� ����
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
					* ��Ŷ�� �������� �������� IP �Ǵ� UDP�� ������ ������ ��Ŷ���۸� ��� ���� �Ұ�����. ( �ش� ���̾������ ����Ʈ�� ��� ���� )
					* �� ��� MAC_FRAME ���̾�ܿ��� ���� ����ü�� �Ľ��ϸ鼭 ó���ϴ� ������ �����Ѵ�.
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
					// ����
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
				
				// �غ�� ��� ������ ����Ͽ� ���� ���� �α׸� �����մϴ�.
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



					// ��ϵ� filter����? ��Ȯ�� match
					if (
						node->INBOUND_filterid == in_INBOUND_filterid &&
						node->OUTBOUND_filterid == in_OUTBOUND_filterid
						)
					{
						RemoveEntryList(&node->Entry);
						// �����Ҵ�� mac ��
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
					LIST_ENTRY* next = current->Flink; // ���� ��带 �̸� ����

					ULONG64 current_nanotimestamp = EDR::Util::Timestamp::Get_LocalTimestamp_Nano();

					EDR::WFP_Filter::Response::Filter::Remove_Response_filter(node->INBOUND_filterid);
					EDR::WFP_Filter::Response::Filter::Remove_Response_filter(node->OUTBOUND_filterid);

					RemoveEntryList(&node->Entry);

					if (node->Mac.AllocatedMacArray)
						ExFreePoolWithTag(node->Mac.AllocatedMacArray, 'macF');

					ExFreePoolWithTag(node, NetworkResponseListAllocTag);

					current = next; // �̸� �����ص� ���� ���� �̵�
				}
				ExReleasePushLockExclusive(&lock);
			}
			VOID Loop_Monitor_Network_Response(PVOID ctx)
			{
				UNREFERENCED_PARAMETER(ctx);
				LARGE_INTEGER interval;
				interval.QuadPart = -5LL * 10 * 1000 * 1000; // 5��

				while (true)
				{
					ExAcquirePushLockExclusive(&lock);
					LIST_ENTRY* current = NetworkResponseListHeader.Flink;
					while (current != &NetworkResponseListHeader)
					{
						auto node = CONTAINING_RECORD(current, NETWORK_RESPONSE_LIST_NODE, Entry);
						LIST_ENTRY* next = current->Flink; // ���� ��带 �̸� ����

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
						current = next; // �̸� �����ص� ���� ���� �̵�
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
						FWPM_FILTER_CONDITION0 condition[2 * BOUND_SIZE]; // IP + PORT �� �� ����

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

							// IP ����
							condition[INBOUND_INDEX * 2].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
							condition[INBOUND_INDEX * 2].matchType = FWP_MATCH_EQUAL;
							condition[INBOUND_INDEX * 2].conditionValue.type = FWP_UINT32;
							condition[INBOUND_INDEX * 2].conditionValue.uint32 = target_ip.S_un.S_addr;

							// PORT ����
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

							// IP ����
							condition[OUTBOUND_INDEX * 2].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
							condition[OUTBOUND_INDEX * 2].matchType = FWP_MATCH_EQUAL;
							condition[OUTBOUND_INDEX * 2].conditionValue.type = FWP_UINT32;
							condition[OUTBOUND_INDEX * 2].conditionValue.uint32 = target_ip.S_un.S_addr;

							// PORT ����
							condition[OUTBOUND_INDEX * 2 + 1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
							condition[OUTBOUND_INDEX * 2 + 1].matchType = FWP_MATCH_EQUAL;
							condition[OUTBOUND_INDEX * 2 + 1].conditionValue.type = FWP_UINT16;
							condition[OUTBOUND_INDEX * 2 + 1].conditionValue.uint16 = RtlUshortByteSwap((UINT16)in_port);

							filter[OUTBOUND_INDEX].numFilterConditions = 2;
							filter[OUTBOUND_INDEX].filterCondition = &condition[OUTBOUND_INDEX * 2];
						}
						

						// Ʈ�����
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
			// ���� �ڵ��� ��ȿ���� ������ ������ ���� ����
			if (EngineHandle == NULL)
			{
				return;
			}

			// 1. ���� �� �ݾƿ� ���� (����� ����)
			for (ULONG32 i = 0; i < NUM_LAYERS; i++)
			{
				// FwpmFilter ����
				if (g_wpmFilterIds[i] != 0)
				{
					FwpmFilterDeleteById(EngineHandle, g_wpmFilterIds[i]);
					g_wpmFilterIds[i] = 0; // ������ ����
				}

				// FwpmCallout ����
				if (g_wpmCalloutIds[i] != 0)
				{
					FwpmCalloutDeleteById(EngineHandle, g_wpmCalloutIds[i]);
					g_wpmCalloutIds[i] = 0; // ������ ����
				}

				// FwpsCallout ��� ���
				if (g_wpsCalloutIds[i] != 0)
				{
					FwpsCalloutUnregisterById(g_wpsCalloutIds[i]);
					g_wpsCalloutIds[i] = 0; // ������ ����
				}
			}

			// 2. ������(Provider) ����
			// providerKey�� ��ȿ�� ��쿡�� �õ�
			if (RtlZeroMemory(&g_providerKey, sizeof(GUID)))
			{
				// �����ڸ� �����ϸ� ���õ� ��� ���Ϳ� �ݾƿ��� �ڵ����� ���ŵ�����,
				// ��������� �ϳ��� �����ϴ� ���� �� �����ϰ� ����մϴ�.
				FwpmProviderDeleteByKey(EngineHandle, &g_providerKey);
			}

			// 3.���� Ǯ ����
			EDR::WFP_Filter::Response::_Cleanup_NetworkResponse();

			// 4. ���� ���� �ڵ� �ݱ�
			FwpmEngineClose(EngineHandle);
			EngineHandle = NULL; // �ڵ��� NULL�� �����Ͽ� �ߺ� ���� ����
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
			len = bufferSize - *actualSize; // ���� ������ ����
		}

		UCHAR* dataPtr = (UCHAR*)NdisGetDataBuffer(netBuffer, len, NULL, 1, 0);
		if (dataPtr) {
			RtlCopyMemory(outBuffer + *actualSize, dataPtr, len);
			*actualSize += len;
		}

		// ù ��° NET_BUFFER���� �������� ��ȣ ����
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
* �� �̻� ������� ���� ( Old ) 
BOOLEAN Get_Packet_Size(void* layerData, ULONG32* PacketSize, ULONG32* ProtocolNumber) {

	// PAGED_CODE(); // CalloutFn�� DISPATCH_LEVEL���� ����� �� �����Ƿ� PAGED_CODE �ּ� ó�� �Ǵ� ����

	if (!layerData || !PacketSize || !ProtocolNumber) {
		return FALSE; // ��ȿ���� ���� ����
	}

	*PacketSize = 0;
	*ProtocolNumber = 0; // �⺻�� �ʱ�ȭ

	NET_BUFFER_LIST* netBufferList = (NET_BUFFER_LIST*)layerData;
	if (netBufferList == NULL) {
		return FALSE;
	}

	NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);

	if (netBuffer != NULL) {
		// ù ��° NET_BUFFER���� IP ��� ������ ���� �õ�
		ULONG packetDataLength = NET_BUFFER_DATA_LENGTH(netBuffer);
		UCHAR* packetData = (UCHAR * )NdisGetDataBuffer(netBuffer, packetDataLength, NULL, 1, 0);

		if (packetData != NULL && packetDataLength >= sizeof(IPV4_HEADER)) {
			// IPv4 ��� ĳ����
			PIPV4_HEADER ipHeader = (PIPV4_HEADER)packetData;

			// IP �������� ��ȣ ����
			*ProtocolNumber = ipHeader->Protocol;
		}

		// ��ü ��Ŷ ������ ���
		NET_BUFFER* currentNetBuffer = netBuffer; // ù ��° NET_BUFFER���� ����
		while (currentNetBuffer != NULL) {
			*PacketSize += NET_BUFFER_DATA_LENGTH(currentNetBuffer);
			currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
		}
	}
	else {
		return FALSE; // NET_BUFFER�� ���� ���
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

	// ������� ���� ( Ʈ����� ���� ) 
	status = FwpmTransactionBegin(EngineHandle, 0);
	if (status != STATUS_SUCCESS) {
		return status;
	}






	/* ===================���� ���� ����============= */

	/* Fwps */
	// ���� key ���� ( �̴� �ݾƿ� Ű ��ȯ )
	GUID Calloutkey = { 0, };
	status = GenerateGUID(&Calloutkey);

	FWPS_CALLOUT3 callout = { 0, };
	callout.calloutKey = Calloutkey; // Fwpm ��Ͻ� �����Ǵ� Ű��

	callout.flags = 0;
	callout.classifyFn = EDR::WFP_Filter::Handler::FwpsCalloutClassifyFn3;
	callout.notifyFn = NotifyFn;
	callout.flowDeleteFn = FlowDeleteFn;

	// Fwps �ݾƿ� ��� ( ��� ��� )
	status = FwpsCalloutRegister3(DeviceObject, &callout, WPS_CalloutId);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	/* Fwpm */
	// wpm�ݾƿ� ��� ( ��å ��� ) 
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

	// WPM ���� ���
	FWPM_FILTER  fwpm_filter = { 0, };
	//fwpm_filter_id
	fwpm_filter.displayData.name = (wchar_t*)L"wfpkm_VATEX_filter";
	fwpm_filter.displayData.description = (wchar_t*)L"The filter object for wfp-VATEX";
	fwpm_filter.layerKey = LayerKey; // �Ķ���ͷ� ������ ���̾� ����
	fwpm_filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	fwpm_filter.action.calloutKey = Calloutkey;

	// ����ġ�� ������ ���� ���� �����.
	fwpm_filter.weight.type = FWP_UINT64; // ����� �ʵ� ����
	UINT64 weight = 0xffffffffffffffff; // ����ġ ����
	fwpm_filter.weight.uint64 = &weight; // ����ġ ����

	status = FwpmFilterAdd(EngineHandle, &fwpm_filter, NULL, WPM_Filterid);
	if (status != STATUS_SUCCESS) {
		return status;
	}



	// �����Ϸ�
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


	// ���� ����
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);
	if (status != STATUS_SUCCESS) {
		return status;
	}


	// ���� ������� ���� ( Ʈ����� ���� ) 
	status = FwpmTransactionBegin(EngineHandle, 0);
	if (status != STATUS_SUCCESS) {
		return status;
	}




	// GUID ��������
	status = GenerateGUID(provider_key);

	// GUID Ű ����
	FWPM_PROVIDER wfp_provider = { 0, };
	wfp_provider.serviceName = (wchar_t*)L"wfpk";
	wfp_provider.displayData.name = (wchar_t*)L"wfpkm_VATEX_provider";
	wfp_provider.displayData.description = (wchar_t*)L"The provider object for wfp-VATEX";

	wfp_provider.providerKey = *provider_key;

	// ������ ���
	status = FwpmProviderAdd(EngineHandle, &wfp_provider, NULL);
	if ((status) != STATUS_SUCCESS) {
		return status;
	}






	// ���� �����Ϸ�
	status = FwpmTransactionCommit(EngineHandle);
	if ((status) != STATUS_SUCCESS) {
		return status;
	}

	return status;
}

NTSTATUS NDIS_PacketFilter_Register(PDEVICE_OBJECT DeviceObject) {
	if (!DeviceObject) return STATUS_INVALID_PARAMETER;
	NTSTATUS status = STATUS_SUCCESS;

	// GUID provider_key = { 0, }; // ���� ���� ��� ���� ���� ���
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "���� ���� �õ�\n");
	status = InitializeFilterEngine(&g_providerKey); // ���� ������ Ű ����
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

	// NUM_LAYERS�� �迭 ũ�Ⱑ ��ġ�ϴ��� Ȯ��
	static_assert(sizeof(LayerKey) / sizeof(GUID) == NUM_LAYERS, "LayerKey array size mismatch with NUM_LAYERS");

	for (ULONG32 i = 0; i < NUM_LAYERS; i++) {
		// ���� ���� ��� ���� �迭�� ID ����
		status = Set_CallOut(
			DeviceObject,
			&g_providerKey,
			LayerKey[i],
			&g_wpsCalloutIds[i],
			&g_wpmCalloutIds[i],
			&g_wpmFilterIds[i]
		);
		if (status != STATUS_SUCCESS) {
			// ���� ��, ���ݱ��� ��ϵ� ���� �����ؾ� ������ �����ϰ� �ϱ� ���� �ٷ� ��ȯ
			// �� �߰��� �ڵ�� ���⼭ UnSet_WFP_Filter�� ȣ���Ͽ� �κ� ����
			return status;
		}
	}

	// ���ܵ��
	EDR::WFP_Filter::Response::_NetworkResponse_Initialize();

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "��Ŷ���� ��� �Ϸ�\n");
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
	if (!NT_SUCCESS(status) )  // RtlIpv4StringToAddressA�� LONG ��ȯ
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

		// ���� �������� �̵� ("-" ��ŵ)
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
	������@@@@@@@@@@@@@@@@@@@@
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
		return STATUS_SUCCESS;  // ��� ��������� ��� ����
	}

	debug_log("Failed to generate UUID, status: %x\n", status);
	return status;
}