#ifndef IOCTL_HPP
#define IOCTL_HPP

#include "Util.hpp"

#define IOCTL_Device_SymbolicName L"\\??\\VATEX_EVIDENTIA_EDR_AGENT"

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


namespace EDR
{
	namespace IOCTL
	{
		class IOCTL
		{
			public:
				~IOCTL() 
				{
					DisconnectIOCTL();
				}

				BOOLEAN INITIALIZE(HANDLE ProcessId, HANDLE APC_THREADID, PVOID APC_HANDLER);

			private:
				
				HANDLE hDevice = NULL;

				BOOLEAN ConnectIOCTL();
				VOID DisconnectIOCTL();

				BOOLEAN DataToKernel(DWORD IOCTLCODE, PVOID Data, SIZE_T DataSize);
		};
	}
}


#endif