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
			로그 가져오고 Kafka 전달 책임
		*/
		class Log_IOCTL : public IOCTL
		{
		public:
			Log_IOCTL() = default;
			~Log_IOCTL() = default; // 부모 소멸자가 자동 호출됨

			BOOLEAN INITIALIZE(HANDLE ProcessId);


			BOOLEAN REQUEST_LOG(PVOID* out_UserAllocatedFileBinaryAddress, ULONG64* out_BinarySize);

		};

		/*
			EDR 서버로부터 명령을 통해 요청하는 IOCTL
		*/
		class EDR_IOCTL : public IOCTL
		{
		public:
			EDR_IOCTL() = default;
			~EDR_IOCTL() = default; // 부모 소멸자가 자동 호출됨


			BOOLEAN REQUEST_FILE();

			BOOLEAN REQUEST_RESPONSE_PROCESS();
			BOOLEAN REQUEST_RESPONSE_FILE();
			BOOLEAN REQUEST_RESPONSE_IP();

		};
	}
}


#endif