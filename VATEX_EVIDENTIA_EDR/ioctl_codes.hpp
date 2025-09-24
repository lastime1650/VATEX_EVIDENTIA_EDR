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
};

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

#endif