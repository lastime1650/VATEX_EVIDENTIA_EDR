#include "ProcessSession.hpp"
#include <algorithm>
#include <vector>
#include <string>
#include <regex> // 정규식 사용
#include <list>  

namespace EDR
{
    namespace Session
    {
        namespace Process
        {
            // 노드 정의
            struct Session_node
            {
                std::string SesssionID;
                HANDLE pid;
                HANDLE ppid;
                bool is_alive;

                // 자식 노드 리스트 (list 사용으로 삽입/삭제 시 포인터 유지)
                std::list<Session_node> Child;

                // 생성자
                Session_node(std::string sid, HANDLE p, HANDLE pp, bool alive)
                    : SesssionID(std::move(sid)), pid(p), ppid(pp), is_alive(alive) {}
            };

            // 탐색 결과 컨텍스트
            struct NodeContext
            {
                Session_node* found = nullptr;
                Session_node* parent = nullptr;
                Session_node* root = nullptr;
            };

            class ProcessSession
            {
            private:
                // Forest 구조: 여러 개의 트리 루트가 존재 가능
                std::list<Session_node> Root;

                // RW Lock: 읽기 많음, 쓰기 적음 패턴에 최적화
                mutable std::shared_mutex session_mutex_;

            private:
                // --- 헬퍼 함수 ---

                // 재귀 탐색
                NodeContext findNodeRecursive(Session_node& currentNode, Session_node* parentNode, Session_node& rootNode, HANDLE pid)
                {
                    if (currentNode.pid == pid) {
                        return { &currentNode, parentNode, &rootNode };
                    }
                    for (auto& child : currentNode.Child) {
                        NodeContext result = findNodeRecursive(child, &currentNode, rootNode, pid);
                        if (result.found) return result;
                    }
                    return {};
                }

                // 전체 탐색
                NodeContext findNodeWithContext(HANDLE pid)
                {
                    for (auto& root : this->Root) {
                        NodeContext result = findNodeRecursive(root, nullptr, root, pid);
                        if (result.found) return result;
                    }
                    return {};
                }

                // Explorer.exe 확인 (최적화됨)
                static bool IsExplorerExe(const std::string& path)
                {
                    if (path.empty()) return false;

                    // 정규식 컴파일 비용 절감을 위해 static const 사용
                    static const std::regex explorer_regex(
                        R"(\\Device\\HarddiskVolume[0-9]+\\Windows\\explorer\.exe)",
                        std::regex_constants::icase | std::regex_constants::optimize
                    );

                    try {
                        return std::regex_match(path, explorer_regex);
                    }
                    catch (...) {
                        return false;
                    }
                }

                // 세션 ID 생성 헬퍼
                std::string GenerateSessionID(HANDLE pid)
                {
                    uint64_t timestamp = 0;
                    EDR::Util::timestamp::Get_Real_Timestamp(&timestamp);
                    std::string NanoIso = EDR::Util::timestamp::To_Nano_Iso8601(timestamp);
                    // PID와 타임스탬프를 조합하여 고유 ID 생성
                    return EDR::Util::hash::sha256FromString(NanoIso + std::to_string(reinterpret_cast<uintptr_t>(pid)));
                }

            public:
                // ==============================================================================
                // [핵심] ProcessCreate
                // 프로세스 생성 이벤트 처리 (부모-자식 연결, Placeholder 계승, 입양, 재배치)
                // ==============================================================================
                bool ProcessCreate(HANDLE pid, HANDLE ppid, std::string ParentImagePath,
                    std::string& out_processSession, std::string& out_root_processSession, std::string& out_parent_processSession)
                {
                    std::lock_guard<std::shared_mutex> lock(session_mutex_);

                    NodeContext existingNodeContext = findNodeWithContext(pid);
                    Session_node* targetNode = nullptr;

                    // 1. 노드 확보 (Placeholder 계승 확인)
                    if (existingNodeContext.found)
                    {
                        // [Case A: Placeholder 계승]
                        targetNode = existingNodeContext.found;

                        // [중요 수정] SessionID는 업데이트하지 않습니다!
                        // AppendingEvent에서 이미 이 ID로 이벤트를 서버에 보냈기 때문입니다.
                        // targetNode->SesssionID = ...; (삭제됨)

                        // [업데이트] 부족했던 정보(PPID, 생존여부)만 채워 넣습니다.
                        targetNode->ppid = ppid;     // 0 -> 실제 PPID
                        targetNode->is_alive = true; // Ghost -> Real
                    }
                    else
                    {
                        // [Case B: 완전 신규 생성]
                        std::string sessionId = GenerateSessionID(pid);

                        // 신규 노드 생성
                        this->Root.emplace_back(sessionId, pid, ppid, true);
                        targetNode = &this->Root.back();
                    }

                    // 2. 트리 재배치 (Relocation) 로직
                    // : Placeholder는 PPID를 몰라서 Root에 있었으나, 이제 PPID를 알게 되었으니 제자리로 보냅니다.

                    bool forceRoot = IsExplorerExe(ParentImagePath);

                    // (1) 내가 Root 리스트에 있고 (부모가 없다고 되어있고)
                    // (2) 강제 Root(Explorer)가 아니며
                    // (3) 실제 부모(PPID)가 존재하는 경우
                    if (!forceRoot && ppid != (HANDLE)0 && ppid != (HANDLE)4)
                    {
                        // 현재 내가 정말 Root 리스트에 있는지 확인 (Placeholder였다면 무조건 Root에 있음)
                        // existingNodeContext.parent == nullptr 인지 확인하거나, Root 리스트에서 검색

                        // 부모 노드 검색
                        NodeContext parentCtx = findNodeWithContext(ppid);

                        if (parentCtx.found)
                        {
                            // 부모를 찾았으므로, 나를 부모 밑으로 이동 (Splice)

                            // 주의: 내가 이미 부모 밑에 잘 있는 경우(Case B에서 신규생성 시 바로 붙인 경우 등)는 제외해야 함.
                            // 하지만 위 로직상 Case B는 일단 Root에 넣었으므로 여기서 이동됨. 
                            // Case A(Placeholder)도 Root에 있었으므로 여기서 이동됨.

                            // Root 리스트에서 나를 찾아서 부모의 Child로 이동
                            auto it = std::find_if(this->Root.begin(), this->Root.end(),
                                [&](const Session_node& n) { return n.pid == pid; });

                            if (it != this->Root.end()) {
                                // Root -> 부모의 Child로 이동 (포인터 유효함)
                                parentCtx.found->Child.splice(parentCtx.found->Child.end(), this->Root, it);
                            }
                        }
                        else
                        {
                            // 부모가 트리에 없음 (부모도 지연된 상태)
                            // -> 부모의 Placeholder를 Root에 생성
                            std::string parentSessionId = GenerateSessionID(ppid);
                            this->Root.emplace_back(parentSessionId, ppid, (HANDLE)0, false); // is_alive=false
                            Session_node* newParent = &this->Root.back();

                            // 나를 그 부모 밑으로 이동
                            auto it = std::find_if(this->Root.begin(), this->Root.end(),
                                [&](const Session_node& n) { return n.pid == pid; });
                            if (it != this->Root.end()) {
                                newParent->Child.splice(newParent->Child.end(), this->Root, it);
                            }
                        }
                    }

                    // 3. 입양 (Adoption) 로직
                    // : 내가 생성됨으로써, 기존에 부모를 잃고 Root에 있던 내 자식들을 데려옵니다.
                    // : 순서가 (자식 Appending -> 자식 Create -> 부모 Create) 순으로 왔을 때 필요
                    auto it = this->Root.begin();
                    while (it != this->Root.end()) {
                        if (it->pid == pid) { // 나 자신은 건너뜀
                            ++it; continue;
                        }

                        if (it->ppid == pid) {
                            // 내 자식 발견! Root에서 내 밑으로 이동
                            auto next_it = std::next(it);
                            targetNode->Child.splice(targetNode->Child.end(), this->Root, it);
                            it = next_it;
                        }
                        else {
                            ++it;
                        }
                    }

                    // 4. 최종 결과 반환
                    // 위치가 이동되었으므로 컨텍스트를 다시 조회하여 정확한 Root/Parent 세션 ID 반환
                    NodeContext finalContext = findNodeWithContext(pid);
                    if (finalContext.found) {
                        out_processSession = finalContext.found->SesssionID;
                        out_root_processSession = finalContext.root->SesssionID;
                        out_parent_processSession = finalContext.parent ? finalContext.parent->SesssionID : finalContext.found->SesssionID;
                        return true;
                    }

                    return false;
                }

                // ==============================================================================
                // [핵심] AppendingEvent
                // 자식 이벤트 처리. 순서가 꼬여서 먼저 오더라도 Placeholder를 생성하여 유효 처리.
                // ==============================================================================
                bool AppendingEvent(HANDLE pid, std::string& out_processSession, std::string& out_root_processSession, std::string& out_parent_processSession)
                {
                    // 1. [Fast Path] 읽기 락 시도
                    {
                        std::shared_lock<std::shared_mutex> read_lock(session_mutex_);
                        NodeContext context = findNodeWithContext(pid);

                        if (context.found) {
                            out_processSession = context.found->SesssionID;
                            out_root_processSession = context.root->SesssionID;
                            out_parent_processSession = context.parent ? context.parent->SesssionID : context.found->SesssionID;
                            return true;
                        }
                    }

                    // 2. [Slow Path] 노드가 없음 -> 순서 꼬임 -> Placeholder 생성 필요
                    // 쓰기 락 획득
                    std::unique_lock<std::shared_mutex> write_lock(session_mutex_);

                    // 더블 체크 (락 획득 대기 중에 다른 스레드가 생성했을 수 있음)
                    NodeContext context = findNodeWithContext(pid);
                    if (context.found) {
                        out_processSession = context.found->SesssionID;
                        out_root_processSession = context.root->SesssionID;
                        out_parent_processSession = context.parent ? context.parent->SesssionID : context.found->SesssionID;
                        return true;
                    }

                    // 3. Placeholder 생성
                    // EDR 서버 전송용 정식 ID 생성
                    std::string sessionId = GenerateSessionID(pid);

                    // 정보 부족: PPID 모름(0), 아직 생성 이벤트 안옴(is_alive=false)
                    // 일단 Root에 배치
                    this->Root.emplace_back(sessionId, pid, (HANDLE)0, false);
                    Session_node* newNode = &this->Root.back();

                    // 4. 결과 반환
                    out_processSession = newNode->SesssionID;
                    out_root_processSession = newNode->SesssionID; // 일단 내가 Root
                    out_parent_processSession = newNode->SesssionID; // 부모 모름 -> 나를 가리킴 (혹은 빈값)

                    return true;
                }

                // ==============================================================================
                // ProcessRemove
                // 프로세스 종료 처리. 자식이 살아있으면 노드 유지(Ghost), 없으면 삭제.
                // ==============================================================================
                bool ProcessRemove(HANDLE pid, std::string& out_processSession, std::string& out_root_processSession, std::string& out_parent_processSession)
                {
                    std::lock_guard<std::shared_mutex> lock(session_mutex_);

                    NodeContext context = findNodeWithContext(pid);
                    if (!context.found) {
                        return false;
                    }

                    out_processSession = context.found->SesssionID;
                    out_root_processSession = context.root->SesssionID;
                    out_parent_processSession = context.parent ? context.parent->SesssionID : context.found->SesssionID;

                    // 죽은 상태로 표시
                    context.found->is_alive = false;

                    // 가지치기 (Pruning)
                    // 재귀 람다를 이용해 하위 노드 검사 및 삭제
                    auto prune = [&](auto&& self, std::list<Session_node>& nodes) -> void {
                        for (auto it = nodes.begin(); it != nodes.end(); ) {
                            // 자식들 먼저 재귀적으로 정리
                            if (!it->Child.empty()) {
                                self(self, it->Child);
                            }

                            // 나도 죽었고(is_alive==false), 자식도 모두 없으면 삭제
                            if (!it->is_alive && it->Child.empty()) {
                                it = nodes.erase(it); // list erase는 반복자 안정성 보장 (반환값은 다음 요소)
                            }
                            else {
                                ++it;
                            }
                        }
                        };

                    // 전체 Root에 대해 가지치기 수행
                    prune(prune, this->Root);

                    return true;
                }
            };
        }
    }
}