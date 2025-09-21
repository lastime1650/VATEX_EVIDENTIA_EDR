#include "util.hpp"
#include "IOCTL.hpp"
#include "DriverUnload.hpp"

#include "NotifyRoutine.hpp"
#include "LogSender.hpp"
#include "Network.hpp"
#include "MiniFilter.hpp"
#include "Registry.hpp"
#include "ObRegisterCallback.hpp"
#include "Response.hpp"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverobject, PUNICODE_STRING registerpath)
{
	UNREFERENCED_PARAMETER(registerpath);
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	// ���� üũ
	status = EDR::Util::SysVersion::VersionCheck();
	if (!NT_SUCCESS(status))
		return status;

	// �ʱ�ȭ
	// 1. LogSender
	EDR::LogSender::INITIALIZE();
	// 2. Response
	EDR::Response::HashTable::Initialize();


	// ��ε� ����
	driverobject->DriverUnload = EDR::UnLoad::DRIVER_UNLOAD;

	// IOCTL ���
	PDEVICE_OBJECT pDevice = NULL;
	status = EDR::IOCTL::INITIALIZE(driverobject,&pDevice);
	if (!NT_SUCCESS(status))
		return status;

	// �̺�Ʈ ��ƾ ����

	// 1. NotifyRoutine
	status = EDR::NotifyRoutines::Load_NotifyRoutines();
	if (!NT_SUCCESS(status))
		return status;

	// 2. Network
	status = EDR::WFP_Filter::Load_WFP_Filter(pDevice);
	if (!NT_SUCCESS(status))
		return status;

	// 3. Filesystem
	status = EDR::MiniFilter::Load_MiniFilter(driverobject);
	if (!NT_SUCCESS(status))
		return status;

	// 4. Registry
	status = EDR::Registry::Load_RegistryCallback(driverobject);
	if (!NT_SUCCESS(status))
		return status;

	// 5. ObRegisterCallback
	status = EDR::ObRegisterCallback::Load_ObRegisterCallbacks();
	if (!NT_SUCCESS(status))
		return status;

	return status;
}