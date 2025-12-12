#ifndef PROCESSSESSION_HPP
#define PROCESSSESSION_HPP

#include "Util.hpp"
#include <shared_mutex> // <--- shared_mutex 헤더 추가

namespace EDR {
    namespace Session {
        namespace Process {

            // 프로세스 트리 노드 구조체
            struct Session_node {
                std::string SesssionID;
                HANDLE pid;
                HANDLE ppid;
                bool is_alive; // 실제 Create 이벤트가 도착했는지 여부 (Placeholder와 구분)
                std::vector<Session_node> Child;
            };

            class ProcessSession {
            private:
                std::vector<Session_node> Root;
                mutable std::shared_mutex session_mutex_;

            public:
                // 프로세스 생성 이벤트 처리
                bool ProcessCreate(
                    HANDLE pid,
                    HANDLE ppid,
                    std::string ParentImagePath,
                    std::string& out_processSession,
                    std::string& out_root_processSession,
                    std::string& out_parent_processSession
                );

                // 기타 이벤트 처리
                bool AppendingEvent(
                    HANDLE pid,
                    std::string& out_processSession,
                    std::string& out_root_processSession,
                    std::string& out_parent_processSession
                );

                // 프로세스 종료 이벤트 처리
                bool ProcessRemove(
                    HANDLE pid,
                    std::string& out_processSession,
                    std::string& out_root_processSession,
                    std::string& out_parent_processSession
                );
            };

        } // namespace Process
    } // namespace Session
} // namespace EDR

#endif