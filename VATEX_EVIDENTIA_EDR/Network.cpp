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
constexpr ULONG NUM_LAYERS = 4; // ���͸��� ���̾� ����
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

BOOLEAN Get_Packet_Size(void* layerData, ULONG32* PacketSize, ULONG32* ProtocolNumber);

NTSTATUS NDIS_PacketFilter_Register(PDEVICE_OBJECT DeviceObject);
NTSTATUS GenerateGUID(_Inout_ GUID* inout_guid);


namespace EDR
{
	namespace WFP_Filter
	{

		namespace Handler
		{
			//#define PACKETBUFFALLOC 'PKBF'
			//#define PACKETBUFFMAXIMUMSIZE 9216 // MTU (15xx + VLAN TAG + JumboFrame.. )
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
				ULONG32 NetworkInterfaceIndex;


				BOOLEAN is_inbound = FALSE;
				ULONG32 protocolNumber = 0;
				ULONG32 packetSize = 0;
				UINT32 localIp = 0;
				UINT16 localPort = 0;
				UINT32 remoteIp = 0;
				UINT16 remotePort = 0;

				switch (inFixedValues->layerId) {
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
				}
				default:
				{
					return;
				}
				}
				Get_Packet_Size(layerData, &packetSize, &protocolNumber);

				if (is_inbound)
				{
					NetworkInterfaceIndex = inMetaValues->destinationInterfaceIndex;
				}
				else
				{
					NetworkInterfaceIndex = inMetaValues->sourceInterfaceIndex;
				}

				CHAR localIpStr[16] = { 0 }; // "xxx.xxx.xxx.xxx" (�ִ� 15��) + NULL
				CHAR remoteIpStr[16] = { 0 };
				IN_ADDR addr;

				// Local IP ��ȯ
				addr.S_un.S_addr = RtlUlongByteSwap(localIp);
				RtlIpv4AddressToStringA(&addr, localIpStr);

				// Remote IP ��ȯ
				addr.S_un.S_addr = RtlUlongByteSwap(remoteIp);
				RtlIpv4AddressToStringA(&addr, remoteIpStr);
				
				// �غ�� ��� ������ ����Ͽ� ���� ���� �α׸� �����մϴ�.
				EDR::LogSender::function::NetworkLog(
					PID,
					NanoTimestamp,

					protocolNumber,

					is_inbound,

					packetSize,

					(PUCHAR)localIpStr,
					(ULONG32)strlen(localIpStr), 
					localPort,
					
					(PUCHAR)remoteIpStr,
					(ULONG32)strlen(remoteIpStr),
					remotePort,

					NetworkInterfaceIndex
				);

				return;
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

			// 3. ���� ���� �ڵ� �ݱ�
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
		FWPM_LAYER_INBOUND_TRANSPORT_V4,
		FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
		FWPM_LAYER_INBOUND_IPPACKET_V4,
		FWPM_LAYER_OUTBOUND_IPPACKET_V4
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
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "��Ŷ���� ��� �Ϸ�\n");
	return status;
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