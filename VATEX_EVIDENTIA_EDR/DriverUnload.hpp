#ifndef DriverUnload_hpp
#define DriverUnload_hpp

#include "util.hpp"

/*
	해제할 전역변수 및 필요한 헤더들
*/

namespace EDR
{
	namespace UnLoad
	{
		VOID DRIVER_UNLOAD( _In_ struct _DRIVER_OBJECT* DriverObject);
	}
}


#endif