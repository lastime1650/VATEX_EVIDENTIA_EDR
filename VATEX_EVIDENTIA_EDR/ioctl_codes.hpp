#ifndef IOCT_CODES
#define IOCT_CODES

#include "util.hpp"

/*
	���� <-> Ŀ�� �� �ʱ�ȭ
*/
#define IOCTL_INIT \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1650, METHOD_BUFFERED, FILE_ANY_ACCESS) // �ʱ�ȭ ���

struct IOCTL_INIT_s
{
	struct
	{
		HANDLE User_AGENT_ProcessId; // ���� ������Ʈ PID
	} input;

	struct
	{
		BOOLEAN is_success;
	}output;
};

#define IOCTL_REQ_FILE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1651, METHOD_BUFFERED, FILE_ANY_ACCESS) // ���� ���̳ʸ� ��û

struct IOCTL_REQ_FILE_s
{
	struct
	{
		CHAR FILEPATH[4096];

	} input;

	struct
	{
		PVOID UserAllocatedFileBinaryAddress;
		ULONG64 BinarySize;
	}output;
};
/*
#define IOCTL_REQ_RESPONSE_FILE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1652, METHOD_BUFFERED, FILE_ANY_ACCESS) // [�����ؽøʵ��] ���� ( SHA256 )

struct IOCTL_REQ_RESPONSE_FILE_s
{
	struct
	{
		CHAR FILEPATH[4096];

	} input;

	struct
	{
		BOOLEAN is_success;
	}output;
};


#define IOCTL_REQ_RESPONSE_IP \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1653, METHOD_BUFFERED, FILE_ANY_ACCESS) // [�����ؽøʵ��] IPaddress ( Ipv4/ipv6 )

struct IOCTL_REQ_RESPONSE_IP_s
{
	struct
	{
		CHAR IpAddress[4096];

	} input;

	struct
	{
		BOOLEAN is_success;
	}output;
};*/

#define IOCTL_REQ_LOG \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1654, METHOD_BUFFERED, FILE_ANY_ACCESS) // [�����ؽøʵ��] IPaddress ( Ipv4/ipv6 )

struct IOCTL_REQ_LOG_s
{
	struct
	{
		// NULL�̸� ����
		PUCHAR BufferAddress; // EDR::LogSender::resource::UserData�� START ���������κ��� �Ҵ�� �����ּҰ�
		SIZE_T BUfferSize;

		BOOLEAN is_success;

	}output;
};


#define IOCTL_API_CALLS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1700, METHOD_BUFFERED, FILE_ANY_ACCESS) // �ʱ�ȭ ���

// ��� ��ŷ/IOCTL �����ʹ� �� ����ü�� ����
#define APIHooked_IOCTL_DATA_Json_Strlen_MaxSize 8096
struct IOCTL_API_CALLS_Data {
	ULONG64 timestamp;
	HANDLE ProcessId;                  // � API���� ����
	CHAR Json[APIHooked_IOCTL_DATA_Json_Strlen_MaxSize];
};


#define IOCTL_DLP_ADD \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2000, METHOD_BUFFERED, FILE_ANY_ACCESS) // DLP - ��å �߰�
struct IOCTL_DLP_WHITELIST_NODE
{
	struct { BOOLEAN is_block; } WRITE;
	struct { BOOLEAN is_block; } READ;
	struct { BOOLEAN is_block; } RENAME;
	struct { BOOLEAN is_block; } OPEN;
	struct { BOOLEAN is_block; } ACCESS_with_EXTERNAL_DEVICES;
	ULONG64 ProcessEXE_FileReferenceNumber;
};
struct IOCTL_DLP_ADD_Data {

	struct {
		ULONG64 FileSize;
		ULONG64 FileReferenceNumber;
	} FILE;

	struct {
		struct {
			struct { BOOLEAN is_block; } WRITE;
			struct { BOOLEAN is_block; } READ;
			struct { BOOLEAN is_block; } RENAME;
			struct { BOOLEAN is_block; } OPEN;
			struct { BOOLEAN is_block; } ACCESS_with_EXTERNAL_DEVICES;
		} Global;

		struct IOCTL_DLP_WHITELIST_NODE WhiteList[512]; // �ִ� 512�� ������
	} Policy;
};

/*
	Response
	// �ǽð� ���� ��ȣ.
	// ���� ����� Ŀ�ο��� �������� �ʵ��� ���� ( ��, ��Ʈ��ũ ������ �Ͻ���(time based cahced) �������� ����)
*/
// ���μ��� ����
#define IOCTL_RESPONSE_PROCESS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3001, METHOD_BUFFERED, FILE_ANY_ACCESS) // Response - PROCESS ������ġ
struct IOCTL_RESPONSE_PROCESS_Data {

	struct
	{
		HANDLE pid = NULL;			// if running, zwterminate
		CHAR exe_file_path[4096];	// if exist, Remove
	}input;

	struct
	{
		BOOLEAN status = FALSE;
	}output;
};

// ��Ʈ��ũ ����
/*
	(note.) ��Ʈ��ũ�� Ŀ�� ������ ��� ����(cached) �Ǹ�, "end_timestamp" Ÿ�ӽ��������������� ������ �ִ´�.
*/
#define IOCTL_RESPONSE_NETWORK \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3002, METHOD_BUFFERED, FILE_ANY_ACCESS) // Response - NETWORK ������ġ
struct IOCTL_RESPONSE_NETWORK_Data {

	struct
	{
		struct
		{
			BOOLEAN is_enable = FALSE;
			CHAR remote_mac[sizeof("00-00-00-00-00-00")];

		}ethernet_layer;

		struct
		{
			BOOLEAN is_enable = FALSE;
			CHAR remote_ip[sizeof("000:000:000:000")];
		}network_layer;

		struct
		{
			BOOLEAN is_enable = FALSE;
			ULONG32 remote_port = 0;
		}transport_layer;


		ULONG64 end_timestamp = 0;		// end cahced response
	}input;

	struct
	{
		BOOLEAN status = FALSE;

	}output;
};

// ���� ����
// ������ġ
#define IOCTL_RESPONSE_FILE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3003, METHOD_BUFFERED, FILE_ANY_ACCESS) // Response - FILE ������ġ
struct IOCTL_RESPONSE_FILE_Data {

	struct
	{
		CHAR file_path[4096];	// if exist, Remove

	}input;

	struct
	{
		BOOLEAN status = FALSE;
	}output;
};

#endif