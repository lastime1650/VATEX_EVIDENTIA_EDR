#ifndef IOCTL_HPP
#define IOCTL_HPP

#include "Util.hpp"

#define IOCTL_Device_SymbolicName L"\\??\\VATEX_EVIDENTIA_EDR_AGENT"

#include "ioctlcodes.hpp"



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

				

				
				HANDLE hDevice = NULL;

				BOOLEAN ConnectIOCTL();
				VOID DisconnectIOCTL();

				BOOLEAN DataToKernel(DWORD IOCTLCODE, PVOID Data, SIZE_T DataSize);
		};

		/*
			�α� �������� Kafka ���� å��
		*/
		class Log_IOCTL : public IOCTL
		{
		public:
			Log_IOCTL() = default;
			~Log_IOCTL() = default; // �θ� �Ҹ��ڰ� �ڵ� ȣ���

			BOOLEAN INITIALIZE(HANDLE ProcessId);


			BOOLEAN REQUEST_LOG(PVOID* out_UserAllocatedFileBinaryAddress, ULONG64* out_BinarySize);

		};

		/*
			EDR �����κ��� ����� ���� ��û�ϴ� IOCTL
		*/
		class EDR_IOCTL : public IOCTL
		{
		public:
			EDR_IOCTL() = default;
			~EDR_IOCTL() = default; // �θ� �Ҹ��ڰ� �ڵ� ȣ���


			BOOLEAN REQUEST_FILE();

			BOOLEAN REQUEST_RESPONSE_PROCESS();
			BOOLEAN REQUEST_RESPONSE_FILE();
			BOOLEAN REQUEST_RESPONSE_IP();

		};
	}
}


#endif