#ifndef NETWORKSESSION_HPP
#define NETWORKSESSION_HPP

#include "../../util.hpp"
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <unordered_map>

namespace EDR
{
	namespace Session
	{
		namespace Network
		{
			// 각 개별 네트워크 세션 식별

			// map:key
			struct NetworkSessionKey
			{
				__u32 ProtocolNumber;
				
				std::string Local_IP; // 현재 머신 기준 소스 IP 
				__u32 Local_PORT;  // 현재 머신 기준 소스 PORT

				std::string Remote_IP; // 현재 머신 기준 목적 IP 
				__u32 Remote_PORT;  // 현재 머신 기준 목적 PORT

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
				// 해시 함수를 오버로드
				std::size_t operator()(const NetworkSessionKey& k) const noexcept
				{
					std::hash<std::string> shash;  
					return std::hash<__u32>()(k.ProtocolNumber) ^
						shash(k.Local_IP) ^
						std::hash<__u32>()(k.Local_PORT) ^
						shash(k.Remote_IP) ^
						std::hash<__u32>()(k.Remote_PORT);
				}
			};

			// map:value 
			struct NetworkSessionInfo
			{
				std::string SessionID;
				__u64 first_seen_nanotimestamp;
				__u64 last_seen_nanotimestamp;
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
					네트워크 세션 검색하는 메서드 1개만 존재. 

					동작방식.

					1. Key 2개 생성 ( LOCAL -> LOCAL, LOCAL ->REMOTE 형태로 2가지 경우의수 ) , 양방향을 한번에 검색
					2-A. 키 둘다 존재하지 않는 경우, 생성( LOCAL -> LOCAL )트래픽 기준으로 생성하고 해당 키와 Data저장 후 처리
					2-B. 키 중 하나라도 존재하는 경우에, 존재하는 경우에. 해당 Data를 업데이트해서 처리
				*/
				bool Get_NetworkSessionInfo(
					__u32 ProtocolNumber,

					std::string Local_IP, // 현재 머신 기준 소스 IP 
					__u32 Local_PORT,  // 현재 머신 기준 소스 PORT

					std::string Remote_IP, // 현재 머신 기준 목적 IP 
					__u32 Remote_PORT,  // 현재 머신 기준 목적 PORT

					NetworkSessionInfo& output
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

					// 양방향부터 탐색시작
					auto it_A = Session.find(SessionKey_A); // 정방향 검색
					auto it_B = Session.find(SessionKey_B); // 역방향 검색

					// + 현재시간
					__u64 nano_timestamp = 0;
					nano_timestamp = EDR::Util::timestamp::Get_Real_Timestamp();

					if (it_A == Session.end() && it_B == Session.end()) {
						// 둘 다 없는 즉 새 세션 생성
						NetworkSessionInfo info;

						std::string SessionSource = Local_IP + std::to_string(Local_PORT) + Remote_IP + std::to_string(Remote_PORT) + std::to_string(nano_timestamp);
						info.SessionID = EDR::Util::hash::sha256FromString(SessionSource);
						info.first_seen_nanotimestamp = nano_timestamp;
						info.last_seen_nanotimestamp = nano_timestamp;

						Session.emplace(SessionKey_A, info);
						output = info;  // 출력으로
						return true;
					}
					else {
						// 기존 세션 갱신
						NetworkSessionInfo& sess = (it_A != Session.end()) ? it_A->second : it_B->second; // 둘 중에 하나는 존재하는가?
						sess.last_seen_nanotimestamp = nano_timestamp;
						output = sess;
						return true;
					}

					return false;
				}

			private:
				std::unordered_map<
					NetworkSessionKey,  // Key
					NetworkSessionInfo,  // Data
					NetworkSessionKeyHash // hasher
				> Session;

				/*
					세션 만료화 ( 타임아웃 처리 ) 
					주기는 1초, 
					mutex와 충돌하지않게 타임아웃확인
				*/
				std::atomic<bool> stop_thread; // 세션 만료화 체크 스레드 제어값
				std::thread network_session_check_thread; // 스레드
				std::mutex mtx;
				__u64 threadsleepsec = 5; // SessionLoopChecker() 스레드 대기시간 초 
				__u64 timeout = 60ULL * 1000000000; // 타임아웃 60초
				
				void SessionLoopChecker()
				{
					while (!stop_thread)
					{
						std::this_thread::sleep_for(std::chrono::seconds(threadsleepsec)); // 5초마다 검사

						__u64 now_nanotimestamp = 0;
						now_nanotimestamp = EDR::Util::timestamp::Get_Real_Timestamp();

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