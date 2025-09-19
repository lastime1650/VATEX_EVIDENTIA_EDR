#ifndef IOCT_CODES
#define IOCT_CODES

#include "util.hpp"

/*
	유저 <-> 커널 간 초기화
*/
#define IOCTL_INIT \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1650, METHOD_BUFFERED, FILE_ANY_ACCESS) // 초기화 통신

struct IOCTL_INIT_s
{
	struct
	{
		HANDLE User_AGENT_ProcessId; // 유저 에이전트 PID

		HANDLE User_APC_ThreadId; // 유저 APC처리 대기 스레드 ID
		PVOID User_APC_Handler_UserAddress; // APC 함수 ( 유저주소임 ) 

	} input;

	struct
	{
		BOOLEAN is_success;
	}output;
};

#define IOCTL_REQ_FILE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1651, METHOD_BUFFERED, FILE_ANY_ACCESS) // 파일 바이너리 요청

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
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1652, METHOD_BUFFERED, FILE_ANY_ACCESS) // [차단해시맵등록] 파일 ( SHA256 )

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
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1653, METHOD_BUFFERED, FILE_ANY_ACCESS) // [차단해시맵등록] IPaddress ( Ipv4/ipv6 )

struct IOCTL_REQ_RESPONSE_IP_s
{
	struct
	{
		CHAR IpAddress[4096];

	} input;

	struct
	{
		NTSTATUS is_success;
	}output;
};

#endif