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

		NTSTATUS Load_WFP_Filter(PDEVICE_OBJECT input_device);
		VOID Cleanup_WFP_Filter();
	}
}


typedef struct _IPV4_HEADER {
	UCHAR VersionAndHeaderLength; // 4 bits Version, 4 bits Header Length (in 32-bit words)
	UCHAR TypeOfService;
	USHORT TotalLength;           // Total Length of the IP Packet
	USHORT Identification;
	USHORT FlagsAndOffset;
	UCHAR TimeToLive;
	UCHAR Protocol;               // This is the IP Protocol number (e.g., 6 for TCP, 17 for UDP)
	USHORT HeaderChecksum;
	ULONG SourceAddress;
	ULONG DestinationAddress;
	// Options
} IPV4_HEADER, * PIPV4_HEADER;

#endif