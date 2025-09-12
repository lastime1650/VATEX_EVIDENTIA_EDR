#include "util.hpp"
#include "IOCTL.hpp"
#include "DriverUnload.hpp"

NTSTATUS DriverEntry(PDRIVER_OBJECT driverobject, PUNICODE_STRING registerpath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	// �ʱ�ȭ


	// ��ε� ����
	driverobject->DriverUnload = EDR::UnLoad::DRIVER_UNLOAD;

	// IOCTL ���
	status = EDR::IOCTL::INITIALIZE(driverobject);
	if (!NT_SUCCESS(status))
		return status;

	// �̺�Ʈ ��ƾ ����

	return status;
}