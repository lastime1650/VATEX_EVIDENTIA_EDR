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

		HANDLE User_APC_ThreadId; // ���� APCó�� ��� ������ ID
		PVOID User_APC_Handler_UserAddress; // APC �Լ� ( �����ּ��� ) 

	} input;

	struct
	{
		NTSTATUS is_success;
	}output;
};


#endif