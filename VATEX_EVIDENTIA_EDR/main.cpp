#include "util.hpp"
#include "IOCTL.hpp"
#include "DriverUnload.hpp"

NTSTATUS DriverEntry(PDRIVER_OBJECT driverobject, PUNICODE_STRING registerpath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	// 초기화


	// 언로드 설정
	driverobject->DriverUnload = EDR::UnLoad::DRIVER_UNLOAD;

	// IOCTL 등록
	status = EDR::IOCTL::INITIALIZE(driverobject);
	if (!NT_SUCCESS(status))
		return status;

	// 이벤트 루틴 설정

	return status;
}