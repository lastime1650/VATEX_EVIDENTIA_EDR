#ifndef NETWORKSESSION_HPP
#define NETWORKSESSION_HPP

#include "Util.hpp"

namespace EDR
{
	namespace Session
	{
		namespace Network
		{
			// 맵 기반 네트워크 연결 관리

			// map:key
			struct NetworkSessionKey
			{
				ULONG32 ProtocolNumber;
				
				std::string Local_IP; // 세션 생성 당시 소스 IP 
				ULONG32 Local_PORT;  // 세션 생성 당시 소스 PORT

				std::string Remote_IP; // 세션 생성 당시 목적 IP 
				ULONG32 Remote_PORT;  // 세션 생성 당시 목적 PORT

				bool operator==(const NetworkSessionKey& other) const noexcept
				{
					return ProtocolNumber == other.ProtocolNumber &&
						Local_IP == other.Local_IP &&
						Local_PORT == other.Local_PORT &&
						Remote_IP == other.Remote_IP &&
						Remote_PORT == other.Remote_PORT;
				}

			};

			// map:hasher
			struct NetworkSessionKeyHash
			{
				// 해시 연산자 오버로딩
				std::size_t operator()(const NetworkSessionKey& k) const noexcept
				{
					std::hash<std::string> shash;  // 문자열을 해시할 때 사용할 std::hash<string>
					return std::hash<ULONG32>()(k.ProtocolNumber) ^
						shash(k.Local_IP) ^
						std::hash<ULONG32>()(k.Local_PORT) ^
						shash(k.Remote_IP) ^
						std::hash<ULONG32>()(k.Remote_PORT);
				}
			};

			// map:value 
			struct NetworkSessionInfo
			{
				std::string SessionID;
				ULONG64 first_seen_nanotimestamp;
				ULONG64 last_seen_nanotimestamp;
			};

			class NetworkSession
			{
			public:
				NetworkSession()
				{
					this->network_session_check_thread = std::thread([this]() { this->SessionLoopChecker(); });
				}
				~NetworkSession()
				{
					stop_thread = true;
					if (network_session_check_thread.joinable())
						network_session_check_thread.join();
				}

				/*
					네트워크 세션 구하는 메서드 1개만 존재. 

					내부적.

					1. Key 2개 생성 ( LOCAL -> LOCAL, LOCAL ->REMOTE 형태로 2가지 가능성 ) , 프로토콜 넘버는 동일
					2-A. 키 두개 존재하지 않은 경우, 본래( LOCAL -> LOCAL )트래픽 정보를 기반으로 해당 키에 Data삽입 후 처리
					2-B. 키 중 하나가 존재하는 경우는, 존재하는 것임. 해당 Data를 가져와서 처리
					

				*/
				BOOLEAN Get_NetworkSessionInfo(
					ULONG32 ProtocolNumber,

					std::string Local_IP, // 세션 생성 당시 소스 IP 
					ULONG32 Local_PORT,  // 세션 생성 당시 소스 PORT

					std::string Remote_IP, // 세션 생성 당시 목적 IP 
					ULONG32 Remote_PORT,  // 세션 생성 당시 목적 PORT


					NetworkSessionInfo& output
				);


			private:

				std::unordered_map<
					NetworkSessionKey,  // Key
					NetworkSessionInfo,  // Data
					NetworkSessionKeyHash // hasher
				> Session;


				/*
					세션 유효성 ( 타임아웃 기반 ) 
					스레드 1개, 
					mutex등 충돌없이 타임아웃확인
				*/
				std::atomic<bool> stop_thread; // 세션 유효성 체크 스레드 부울값
				std::thread network_session_check_thread; // 세션
				std::mutex mtx;
				ULONG64 threadsleepsec = 5; // SessionLoopChecker() 스레드 대기시간 초 
				ULONG64 timeout = 60ULL * 1000000000; // 타임아웃 60초
				
				void SessionLoopChecker()
				{
					while (!stop_thread)
					{

						std::this_thread::sleep_for(std::chrono::seconds(threadsleepsec)); // 5초마다 검사

						ULONG64 now_nanotimestamp = 0;
						EDR::Util::timestamp::Get_Real_Timestamp(&now_nanotimestamp);

						std::lock_guard<std::mutex> lock(mtx);

						for (auto it = Session.begin(); it != Session.end(); )
						{
							NetworkSessionInfo& value = it->second;
							
							if (now_nanotimestamp > (value.last_seen_nanotimestamp + timeout))
							{
								it = Session.erase(it);
							}
							else
								++it;
						}

					}
				}

				
			};
		}
	}
}

#endif