#ifndef RESPONSE_HPP
#define RESPONSE_HPP

#include "util.hpp"
#include "EventLog.hpp"

// ���� ��ġ 
/*
	��å ������ ������忡 ����. 
	Ŀ���� ������忡 �����ϰ� Struct �� ĳ�����Ͽ� ������ġ
*/
namespace EDR
{
	namespace Response
	{
		namespace Enum
		{
			enum Response_Enum
			{
				Allow, // ����
				Denied, // ����
				Delete // ���� ( ���� �� �������� � ��ȿ )
			};
		}

		namespace FileSystem
		{
			namespace Enum
			{
				enum FileSystem_Response_Action_Enum
				{
					// ���� ����ȭ
					create = EDR::EventLog::Enum::FileSystem::create,
					read = EDR::EventLog::Enum::FileSystem::read,
					write = EDR::EventLog::Enum::FileSystem::write,
					rename = EDR::EventLog::Enum::FileSystem::rename
				};

			}
			// ���� ����
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
			// ���� ����
			namespace Struct
			{
				struct Process_Response
				{

				};
			}
		}
		namespace Network
		{
			// ���� ����
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