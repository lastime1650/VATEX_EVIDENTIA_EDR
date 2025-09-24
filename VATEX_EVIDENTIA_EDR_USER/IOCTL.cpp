#include "IOCTL.hpp"

namespace EDR
{
	namespace IOCTL
	{
		BOOLEAN Log_IOCTL::INITIALIZE(HANDLE ProcessId)
		{
			if (!ConnectIOCTL() || !hDevice)
				return false;


			struct IOCTL_INIT_s init_req_data;
			init_req_data.input.User_AGENT_ProcessId = ProcessId;
			init_req_data.output.is_success = 0;

			if (!DataToKernel(
				IOCTL_INIT,
				&init_req_data,
				sizeof(init_req_data)
			))
			{
				DisconnectIOCTL();
				return false;
			}

			return true;
		}

		BOOLEAN Log_IOCTL::REQUEST_LOG(PVOID* out_UserAllocatedFileBinaryAddress, ULONG64* out_BinarySize)
		{

			if (!ConnectIOCTL() || !hDevice)
				return false;


			struct IOCTL_REQ_LOG_s log_req_data;
			RtlZeroMemory(&log_req_data, sizeof(log_req_data));

			if (!DataToKernel(
				IOCTL_REQ_LOG,
				&log_req_data,
				sizeof(log_req_data)
			)
			)
			{
				DisconnectIOCTL();
				return false;
			}

			*out_UserAllocatedFileBinaryAddress = (PVOID)log_req_data.output.BufferAddress;
			*out_BinarySize = log_req_data.output.BUfferSize;


			return log_req_data.output.is_success;
		}













		BOOLEAN IOCTL::ConnectIOCTL()
		{
			hDevice = CreateFileW(
				IOCTL_Device_SymbolicName,
				GENERIC_READ | GENERIC_WRITE,
				0,
				NULL,
				OPEN_EXISTING,
				0,
				NULL
			);
			if (hDevice == INVALID_HANDLE_VALUE)
			{
				hDevice = NULL;
				return false;
			}

			return true;
		}
		VOID IOCTL::DisconnectIOCTL()
		{
			if (!hDevice || hDevice == INVALID_HANDLE_VALUE)
				return;
			CloseHandle(hDevice);
			hDevice = NULL;
		}
		BOOLEAN IOCTL::DataToKernel(DWORD IOCTLCODE,  PVOID Data,  SIZE_T DataSize)
		{
			DWORD returnbytes = 0;
			return (BOOLEAN)DeviceIoControl(
				hDevice,
				IOCTLCODE,

				Data,
				DataSize,
				Data,
				DataSize,

				&returnbytes,

				NULL
			);
		}
	}
}