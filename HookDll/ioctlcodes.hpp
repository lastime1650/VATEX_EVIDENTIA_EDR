#ifndef IOCTL_CODES_HPP
#define IOCTL_CODES_HPP

#include <Windows.h>
#include <devioctl.h>

#define IOCTL_API_CALLS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1700, METHOD_BUFFERED, FILE_ANY_ACCESS) // 초기화 통신

// 모든 후킹/IOCTL 데이터는 이 구조체로 통일
#define APIHooked_IOCTL_DATA_Json_Strlen_MaxSize 8096
struct IOCTL_API_CALLS_Data {
    ULONG64 timestamp;
    HANDLE ProcessId;                  // 어떤 API인지 구분
    CHAR Json[APIHooked_IOCTL_DATA_Json_Strlen_MaxSize];
};

#endif