#include "ProcessSession.hpp"
#include <algorithm>
#include <vector>
#include <string>
#include <regex> // 정규식 사용

namespace EDR
{
    namespace Session
    {
        namespace Process
        {
            // --- 정적 헬퍼 함수 ---

            struct NodeContext
            {
                Session_node* found = nullptr;
                Session_node* parent = nullptr;
                Session_node* root = nullptr;
            };

            // 재귀적으로 노드 탐색
            static NodeContext findNodeRecursive(Session_node& currentNode, Session_node* parentNode, Session_node& rootNode, HANDLE pid)
            {
                if (currentNode.pid == pid) { // is_alive 체크는 외부에서 필요에 따라 수행
                    return { &currentNode, parentNode, &rootNode };
                }
                for (auto& child : currentNode.Child) {
                    NodeContext result = findNodeRecursive(child, &currentNode, rootNode, pid);
                    if (result.found) return result;
                }
                return {};
            }

            // 전체 트리에서 노드 탐색
            static NodeContext findNodeWithContext(std::vector<struct Session_node>& roots, HANDLE pid)
            {
                for (auto& root : roots) {
                    NodeContext result = findNodeRecursive(root, nullptr, root, pid);
                    if (result.found) return result;
                }
                return {};
            }

            // 정규식을 이용한 explorer.exe 경로 검증
            static bool IsExplorerExe(const std::string& path)
            {
                if (path.empty()) return false;

                // C++ 정규식은 백슬래시를 이스케이프해야 함 (\\ -> \\\\)
                // 패턴: \Device\HarddiskVolume[숫자1~100자리]\Windows\explorer.exe (대소문자 무시)
                try {
                    std::regex explorer_regex(
                        "\\\\Device\\\\HarddiskVolume[0-9]+\\\\Windows\\\\explorer\\.exe",
                        std::regex_constants::icase // 대소문자 무시 플래그
                    );
                    return std::regex_match(path, explorer_regex);
                }
                catch (const std::regex_error&) {
                    // 정규식 컴파일 실패 시 안전하게 false 반환
                    return false;
                }
            }

            // --- ProcessSession 클래스 메서드 구현 ---

            bool ProcessSession::ProcessCreate(HANDLE pid, HANDLE ppid,  std::string ParentImagePath, std::string& out_processSession, std::string& out_root_processSession, std::string& out_parent_processSession)
            {
                // 쓰기 작업을 위해 독점 락(Exclusive Lock)을 겁니다.
                std::lock_guard<std::shared_mutex> lock(session_mutex_);

                // 1. 이벤트 대상(pid)이 이미 Placeholder로 존재하는지 확인
                NodeContext existingNodeContext = findNodeWithContext(this->Root, pid);
                Session_node* targetNode = nullptr;

                if (existingNodeContext.found)
                {
                    // [Case A: Placeholder 계승] - 내가 누군가의 가상 부모였음.
                    targetNode = existingNodeContext.found;
                    // 가상 노드를 실제 정보로 업데이트
                    uint64_t timestamp = 0;
                    EDR::Util::timestamp::Get_Real_Timestamp(&timestamp);
                    std::string NanoIso = EDR::Util::timestamp::To_Nano_Iso8601(timestamp);
                    targetNode->SesssionID = EDR::Util::hash::sha256FromString(NanoIso + std::to_string(reinterpret_cast<uintptr_t>(pid)));
                    targetNode->ppid = ppid;
                    targetNode->is_alive = true; // 실제 노드로 활성화
                }
                else
                {
                    // [Case B: 완전 신규 노드]
                    uint64_t timestamp = 0;
                    EDR::Util::timestamp::Get_Real_Timestamp(&timestamp);
                    std::string NanoIso = EDR::Util::timestamp::To_Nano_Iso8601(timestamp);
                    std::string sessionId = EDR::Util::hash::sha256FromString(NanoIso + std::to_string(reinterpret_cast<uintptr_t>(pid)));

                    Session_node newNode{ sessionId, pid, ppid, true, {} };

                    // 부모를 찾거나, 없으면 Placeholder 생성하여 그 밑에 추가
                    bool forceRoot = IsExplorerExe(ParentImagePath);
                    if (!forceRoot && ppid != (HANDLE)0 && ppid != (HANDLE)4) {
                        NodeContext parentCtx = findNodeWithContext(this->Root, ppid);
                        Session_node* parentNode = parentCtx.found;
                        if (!parentNode) {
                            // 부모가 없으면 Placeholder 생성
                            std::string tempSessionId = "placeholder_" + std::to_string(reinterpret_cast<uintptr_t>(ppid));
                            this->Root.emplace_back(Session_node{ tempSessionId, ppid, (HANDLE)0, false, {} });
                            parentNode = &this->Root.back();
                        }
                        parentNode->Child.push_back(std::move(newNode));
                        targetNode = &parentNode->Child.back();
                    }
                    else {
                        // 새로운 Root가 됨
                        this->Root.push_back(std::move(newNode));
                        targetNode = &this->Root.back();
                    }
                }

                // 2. 입양(Adoption) 로직: 내가 부모인 고아 Root들을 찾아 내 자식으로 편입
                auto it = this->Root.begin();
                while (it != this->Root.end()) {
                    if (&(*it) == targetNode) {
                        ++it; continue;
                    }
                    if (it->ppid == pid) {
                        targetNode->Child.push_back(std::move(*it));
                        it = this->Root.erase(it);
                    }
                    else {
                        ++it;
                    }
                }

                // 3. 재배치(Relocation) 로직: 내가 Root인데, 내 부모가 다른 트리에 있다면 그 밑으로 이동
                if (targetNode && targetNode->ppid != (HANDLE)0 && targetNode->ppid != (HANDLE)4) {
                    NodeContext myCurrentContext = findNodeWithContext(this->Root, pid);
                    if (myCurrentContext.found && myCurrentContext.parent == nullptr) { // 내가 Root일 때
                        NodeContext realParentContext = findNodeWithContext(this->Root, targetNode->ppid);
                        if (realParentContext.found && realParentContext.root != myCurrentContext.root) {
                            realParentContext.found->Child.push_back(std::move(*myCurrentContext.found));
                            // Root 목록에서 기존의 나를 제거
                            this->Root.erase(std::remove_if(this->Root.begin(), this->Root.end(),
                                [&](const Session_node& node) { return node.pid == pid; }), this->Root.end());
                        }
                    }
                }

                // 4. 최종 세션 ID 계산 및 반환
                NodeContext finalContext = findNodeWithContext(this->Root, pid);
                if (finalContext.found) {
                    out_processSession = finalContext.found->SesssionID;
                    out_root_processSession = finalContext.root->SesssionID;
                    out_parent_processSession = finalContext.parent ? finalContext.parent->SesssionID : finalContext.found->SesssionID;
                }
                else {
                    // 이론상 도달 불가
                    return false;
                }

                return true;
            }

            bool ProcessSession::AppendingEvent(HANDLE pid, std::string& out_processSession, std::string& out_root_processSession, std::string& out_parent_processSession)
            {
                // 읽기 작업을 위해 공유 락(Shared Lock)을 겁니다.
                std::shared_lock<std::shared_mutex> lock(session_mutex_);

                NodeContext context = findNodeWithContext(this->Root, pid);
                // is_alive가 true인 실제 노드만 유효한 것으로 간주
                if (context.found && context.found->is_alive)
                {
                    out_processSession = context.found->SesssionID;
                    out_root_processSession = context.root->SesssionID;
                    out_parent_processSession = context.parent ? context.parent->SesssionID : context.found->SesssionID;
                    return true;
                }
                return false;
            }

            bool ProcessSession::ProcessRemove(HANDLE pid, std::string& out_processSession, std::string& out_root_processSession, std::string& out_parent_processSession)
            {
                // 쓰기 작업을 위해 독점 락(Exclusive Lock)을 겁니다.
                std::lock_guard<std::shared_mutex> lock(session_mutex_);

                NodeContext context = findNodeWithContext(this->Root, pid);
                if (!context.found)
                {
                    return false;
                }

                // 종료 이벤트는 is_alive 여부와 상관없이 처리
                out_processSession = context.found->SesssionID;
                out_root_processSession = context.root->SesssionID;
                out_parent_processSession = context.parent ? context.parent->SesssionID : context.found->SesssionID;

                context.found->is_alive = false;

                // 가지치기 헬퍼 함수
                auto canBePruned = [](const Session_node& node, auto& self) -> bool {
                    if (node.is_alive) return false;
                    for (const auto& child : node.Child) {
                        if (!self(child, self)) return false;
                    }
                    return true;
                    };
                auto attemptToPrune = [&](std::vector<Session_node>& nodes, auto& self) -> void {
                    nodes.erase(std::remove_if(nodes.begin(), nodes.end(), [&](const Session_node& node) {
                        return canBePruned(node, canBePruned);
                        }), nodes.end());
                    for (auto& node : nodes) {
                        self(node.Child, self);
                    }
                    };

                attemptToPrune(this->Root, attemptToPrune);

                return true;
            }
        }
    }
}