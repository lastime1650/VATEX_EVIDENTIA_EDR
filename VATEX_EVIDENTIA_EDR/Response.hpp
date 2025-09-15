#ifndef RESPONSE_HPP
#define RESPONSE_HPP

#include "util.hpp"
#include "EventLog.hpp"

// 차단 조치 
/*
	정책 저장은 유저모드에 있음. 
	커널이 유저모드에 접근하고 Struct 로 캐스팅하여 차단조치
*/
namespace EDR
{
	namespace Response
	{
		namespace Enum
		{
			enum Response_Enum
			{
				Allow, // 승인
				Denied, // 거절
				Delete // 삭제 ( 파일 및 실행파일 등에 유효 )
			};
		}

		namespace FileSystem
		{
			namespace Enum
			{
				enum FileSystem_Response_Action_Enum
				{
					// 값은 동기화
					create = EDR::EventLog::Enum::FileSystem::create,
					read = EDR::EventLog::Enum::FileSystem::read,
					write = EDR::EventLog::Enum::FileSystem::write,
					rename = EDR::EventLog::Enum::FileSystem::rename
				};

			}
			// 차단 정보
			namespace Struct
			{
				struct FileSystem_Response
				{
					EDR::Response::Enum::Response_Enum Response_TODO;


					Enum::FileSystem_Response_Action_Enum Action;
					

				};
			}
		}
		namespace Process
		{
			// 차단 정보
			namespace Struct
			{
				struct Process_Response
				{

				};
			}
		}
		namespace Network
		{
			// 차단 정보
			namespace Struct
			{
				struct Process_Response
				{
					CHAR RemoteIP[16];

				};
			}
		}
	}
}

#endif