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
		NTSTATUS is_success;
	}output;
};


#endif