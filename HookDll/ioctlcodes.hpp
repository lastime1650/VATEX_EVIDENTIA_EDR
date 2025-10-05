#ifndef IOCTL_CODES_HPP
#define IOCTL_CODES_HPP

#include <Windows.h>
#include <devioctl.h>

#define IOCTL_API_CALLS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1700, METHOD_BUFFERED, FILE_ANY_ACCESS) // �ʱ�ȭ ���

// ��� ��ŷ/IOCTL �����ʹ� �� ����ü�� ����
#define APIHooked_IOCTL_DATA_Json_Strlen_MaxSize 8096
struct IOCTL_API_CALLS_Data {
    ULONG64 timestamp;
    HANDLE ProcessId;                  // � API���� ����
    CHAR Json[APIHooked_IOCTL_DATA_Json_Strlen_MaxSize];
};

#endif