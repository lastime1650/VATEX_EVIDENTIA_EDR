#ifndef DriverUnload_hpp
#define DriverUnload_hpp

#include "util.hpp"

/*
	������ �������� �� �ʿ��� �����
*/

namespace EDR
{
	namespace UnLoad
	{
		VOID DRIVER_UNLOAD( _In_ struct _DRIVER_OBJECT* DriverObject);
	}
}


#endif