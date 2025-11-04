#ifndef ETW_PROVIDERS_HPP_
#define ETW_PROVIDERS_HPP_

#include <krabs.hpp>

namespace EDR
{
	namespace ETW
	{
		namespace DOTNET
		{
			namespace Providers
			{
				#define DOTNET_RUNTIME_PROVIDER_GUID L"{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}"
				const krabs::guid dotnet_runtime_t_provider_guid(DOTNET_RUNTIME_PROVIDER_GUID);
			}
		}
	}
}


#endif