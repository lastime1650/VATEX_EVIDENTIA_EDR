#include "NetworkSession.hpp"

namespace EDR
{
	namespace Session
	{
		namespace Network
		{

			BOOLEAN NetworkSession::Get_NetworkSessionInfo(
				ULONG32 ProtocolNumber,

				std::string Local_IP, // ���� ���� ��� �ҽ� IP 
				ULONG32 Local_PORT,  // ���� ���� ��� �ҽ� PORT

				std::string Remote_IP, // ���� ���� ��� ���� IP 
				ULONG32 Remote_PORT,  // ���� ���� ��� ���� PORT

				NetworkSessionInfo& output
			)
			{

				NetworkSessionKey SessionKey_A; // ������ Ű
				NetworkSessionKey SessionKey_B; // ������ Ű

				// ����ü �ʱ�ȭ
				// ������ Ű
				SessionKey_A.ProtocolNumber = ProtocolNumber;
				SessionKey_A.Local_IP = Local_IP;
				SessionKey_A.Local_PORT = Local_PORT;
				SessionKey_A.Remote_IP = Remote_IP;
				SessionKey_A.Remote_PORT = Remote_PORT;

				// ������ Ű
				SessionKey_B.ProtocolNumber = ProtocolNumber;
				SessionKey_B.Local_IP = Remote_IP;
				SessionKey_B.Local_PORT = Remote_PORT;
				SessionKey_B.Remote_IP = Local_IP;
				SessionKey_B.Remote_PORT = Local_PORT;

				// mutex
				std::lock_guard<std::mutex> lock(mtx);

				// �����κ��� Ž������
				auto it_A = Session.find(SessionKey_A); // ������ ���
				auto it_B = Session.find(SessionKey_B); // ������ ���

				// + ����ð�
				ULONG64 nano_timestamp = 0;
				EDR::Util::timestamp::Get_Real_Timestamp(&nano_timestamp);

				if (it_A == Session.end() && it_B == Session.end()) {
					// �� �� ���� �� �� ���� ����
					NetworkSessionInfo info;

					std::string SessionSource = Local_IP + std::to_string(Local_PORT) + Remote_IP + std::to_string(Remote_PORT) + std::to_string(nano_timestamp);
					info.SessionID = EDR::Util::hash::sha256FromString(SessionSource);
					info.first_seen_nanotimestamp = nano_timestamp;
					info.last_seen_nanotimestamp = nano_timestamp;

					Session.emplace(SessionKey_A, info);
					output = info;  // ��¿�
					return TRUE;
				}
				else {
					// ���� ���� ����
					NetworkSessionInfo& sess = (it_A != Session.end()) ? it_A->second : it_B->second; // �� �߿� �ϳ� �����Ѱ�?
					sess.last_seen_nanotimestamp = nano_timestamp;
					output = sess;
					return TRUE;
				}

				return FALSE;
			}

		}
	}
}