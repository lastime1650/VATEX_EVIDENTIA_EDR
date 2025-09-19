#ifndef PROCESSSESSION_HPP
#define PROCESSSESSION_HPP

#include "Util.hpp"

namespace EDR
{
	namespace Session
	{
		namespace Process
		{
			struct Session_node
			{
				std::string SesssionID;

				HANDLE pid;
				bool is_alive;

				std::vector<struct Session_node> Child;
			};

			class ProcessSession
			{
			public:
				ProcessSession() = default;
				~ProcessSession() = default;

				// 프로세스 생성시
				bool ProcessCreate(HANDLE pid, HANDLE ppid, std::string& out_processSession);

				// 프로세스 종료시
				bool ProcessRemove(HANDLE pid, std::string& out_processSession);

				// 그외 이벤트들 모두 
				bool AppendingEvent(HANDLE pid, std::string& out_processSession);

			private:
				std::vector<struct Session_node> Root;

				//std::unordered_map<HANDLE, Session_node*> pid_to_node_map;
			};
		}
	}
}

#endif