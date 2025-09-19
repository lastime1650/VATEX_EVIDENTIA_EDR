#ifndef Windows___hpp
#define Windows___hpp



#include <Windows.h>
#include <string>

#include <vector>
#include <comdef.h>
#include <Wbemidl.h>
#include <sddl.h>     // SID 관련 함수

namespace EDR
{
	namespace Util
	{
		namespace Windows
		{
			
			std::string ReadSMBIOSType1And2();

			BOOLEAN SID_to_Username(std::string sid, std::string& username);
			
		}
	}
}

#endif