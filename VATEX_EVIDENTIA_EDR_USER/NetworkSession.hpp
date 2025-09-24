#ifndef NETWORKSESSION_HPP
#define NETWORKSESSION_HPP

#include "Util.hpp"

namespace EDR
{
	namespace Session
	{
		namespace Network
		{
			// �� ��� ��Ʈ��ũ ���� ����

			// map:key
			struct NetworkSessionKey
			{
				ULONG32 ProtocolNumber;
				
				std::string Local_IP; // ���� ���� ��� �ҽ� IP 
				ULONG32 Local_PORT;  // ���� ���� ��� �ҽ� PORT

				std::string Remote_IP; // ���� ���� ��� ���� IP 
				ULONG32 Remote_PORT;  // ���� ���� ��� ���� PORT

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
				// �ؽ� ������ �����ε�
				std::size_t operator()(const NetworkSessionKey& k) const noexcept
				{
					std::hash<std::string> shash;  // ���ڿ��� �ؽ��� �� ����� std::hash<string>
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
					��Ʈ��ũ ���� ���ϴ� �޼��� 1���� ����. 

					������.

					1. Key 2�� ���� ( LOCAL -> LOCAL, LOCAL ->REMOTE ���·� 2���� ���ɼ� ) , �������� �ѹ��� ����
					2-A. Ű �ΰ� �������� ���� ���, ����( LOCAL -> LOCAL )Ʈ���� ������ ������� �ش� Ű�� Data���� �� ó��
					2-B. Ű �� �ϳ��� �����ϴ� ����, �����ϴ� ����. �ش� Data�� �����ͼ� ó��
					

				*/
				BOOLEAN Get_NetworkSessionInfo(
					ULONG32 ProtocolNumber,

					std::string Local_IP, // ���� ���� ��� �ҽ� IP 
					ULONG32 Local_PORT,  // ���� ���� ��� �ҽ� PORT

					std::string Remote_IP, // ���� ���� ��� ���� IP 
					ULONG32 Remote_PORT,  // ���� ���� ��� ���� PORT


					NetworkSessionInfo& output
				);


			private:

				std::unordered_map<
					NetworkSessionKey,  // Key
					NetworkSessionInfo,  // Data
					NetworkSessionKeyHash // hasher
				> Session;


				/*
					���� ��ȿ�� ( Ÿ�Ӿƿ� ��� ) 
					������ 1��, 
					mutex�� �浹���� Ÿ�Ӿƿ�Ȯ��
				*/
				std::atomic<bool> stop_thread; // ���� ��ȿ�� üũ ������ �οﰪ
				std::thread network_session_check_thread; // ����
				std::mutex mtx;
				ULONG64 threadsleepsec = 5; // SessionLoopChecker() ������ ���ð� �� 
				ULONG64 timeout = 60ULL * 1000000000; // Ÿ�Ӿƿ� 60��
				
				void SessionLoopChecker()
				{
					while (!stop_thread)
					{

						std::this_thread::sleep_for(std::chrono::seconds(threadsleepsec)); // 5�ʸ��� �˻�

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