#ifndef IOCTL_CODES
#define IOCTL_CODES

#include <Windows.h>
#include <winioctl.h>

#define IOCTL_INIT \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1650, METHOD_BUFFERED, FILE_ANY_ACCESS) // 초기화 통신

struct IOCTL_INIT_s
{
	struct
	{
		HANDLE User_AGENT_ProcessId; // 유저 에이전트 PID
	} input;

	struct
	{
		BOOLEAN is_success;
	}output;
};
/*
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
		BOOLEAN is_success;
	}output;
};
*/
#define IOCTL_REQ_LOG \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1654, METHOD_BUFFERED, FILE_ANY_ACCESS) // [차단해시맵등록] IPaddress ( Ipv4/ipv6 )

struct IOCTL_REQ_LOG_s
{
	struct
	{
		// NULL이면 실패
		PUCHAR BufferAddress; // EDR::LogSender::resource::UserData의 START 전역변수로부터 할당된 가상주소값
		SIZE_T BUfferSize;

		BOOLEAN is_success;

	}output;
};

/*
	Response
	// 실시간 차단 선호.
	// 차단 등록을 커널에서 저장하지 않도록 주의 ( 단, 네트워크 차단은 일시적(time based cahced) 차단으로 이해)
*/
// 프로세스 차단
#define IOCTL_RESPONSE_PROCESS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3001, METHOD_BUFFERED, FILE_ANY_ACCESS) // Response - PROCESS 차단조치
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

// 네트워크 차단
/*
	(note.) 네트워크는 커널 레벨에 잠시 저장(cached) 되며, "end_timestamp" 타임스탬프설정값까지 가지고 있는다.
*/
#define IOCTL_RESPONSE_NETWORK \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3002, METHOD_BUFFERED, FILE_ANY_ACCESS) // Response - NETWORK 차단조치
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

// 파일 차단
// 삭제조치
#define IOCTL_RESPONSE_FILE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3003, METHOD_BUFFERED, FILE_ANY_ACCESS) // Response - FILE 차단조치
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