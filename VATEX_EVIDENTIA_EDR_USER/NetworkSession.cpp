#include "NetworkSession.hpp"

namespace EDR
{
	namespace Session
	{
		namespace Network
		{

			BOOLEAN NetworkSession::Get_NetworkSessionInfo(
				const HANDLE& ProcessId,

				ULONG32 ProtocolNumber,

				std::string Local_IP, // 세션 생성 당시 소스 IP 
				ULONG32 Local_PORT,  // 세션 생성 당시 소스 PORT

				std::string Remote_IP, // 세션 생성 당시 목적 IP 
				ULONG32 Remote_PORT,  // 세션 생성 당시 목적 PORT

				NetworkSessionInfo& output,
				bool* is_new
			)
			{

				NetworkSessionKey SessionKey_A; // 정방향 키
				NetworkSessionKey SessionKey_B; // 역방향 키

				// 구조체 초기화
				// 정방향 키
				SessionKey_A.ProtocolNumber = ProtocolNumber;
				SessionKey_A.Local_IP = Local_IP;
				SessionKey_A.Local_PORT = Local_PORT;
				SessionKey_A.Remote_IP = Remote_IP;
				SessionKey_A.Remote_PORT = Remote_PORT;

				// 역방향 키
				SessionKey_B.ProtocolNumber = ProtocolNumber;
				SessionKey_B.Local_IP = Remote_IP;
				SessionKey_B.Local_PORT = Remote_PORT;
				SessionKey_B.Remote_IP = Local_IP;
				SessionKey_B.Remote_PORT = Local_PORT;

				// mutex
				std::lock_guard<std::mutex> lock(mtx);

				// 맵으로부터 탐색시작
				auto it_A = Session.find(SessionKey_A); // 정방향 결과
				auto it_B = Session.find(SessionKey_B); // 역방향 결과

				// + 현재시간
				ULONG64 nano_timestamp = 0;
				EDR::Util::timestamp::Get_Real_Timestamp(&nano_timestamp);

				if (it_A == Session.end() && it_B == Session.end()) {
					// 둘 다 없음 → 새 세션 생성
					NetworkSessionInfo info;

					std::string SessionSource = Local_IP + std::to_string(Local_PORT) + Remote_IP + std::to_string(Remote_PORT) + std::to_string(nano_timestamp);
					info.SessionID = EDR::Util::hash::sha256FromString(SessionSource);
					info.first_seen_nanotimestamp = nano_timestamp;
					info.last_seen_nanotimestamp = nano_timestamp;
					info.ReleatedPids[ProcessId] = true;

					Session.emplace(SessionKey_A, info);
					output = info;  // 출력용
					if (is_new)
						*is_new = true;
					return TRUE;
				}
				else {
					// 기존 세션 갱신
					NetworkSessionInfo& sess = (it_A != Session.end()) ? it_A->second : it_B->second; // 둘 중에 하나 존재한가?
					sess.last_seen_nanotimestamp = nano_timestamp;
					output = sess;

					if (sess.ReleatedPids.find(ProcessId) == sess.ReleatedPids.end())
					{
						// 다른 녀석임 -> 연결 세션은 이미 이전 Process와 다르다는 의미.
						// 주로 비연결형에서 나타난다.

						// 등록한다
						sess.ReleatedPids[ProcessId] = true;

						if (is_new)
							*is_new = true;
					}
					else
					{
						// 같음. (기대하는 것)
						if (is_new)
							*is_new = false;
					}

					
					return TRUE;
				}
				if (is_new)
					*is_new = false;
				return FALSE;
			}

		}
	}
}