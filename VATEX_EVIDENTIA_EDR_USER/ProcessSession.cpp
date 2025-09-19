#include "ProcessSession.hpp"

#include "ProcessSession.hpp"
#include <algorithm> // std::find_if, std::remove_if 사용을 위해 포함

// 참고: behavior_tree.hpp의 Util 함수들이 필요합니다.
// EDR::Util::timestamp 네임스페이스와 EDR::Util::hash 네임스페이스가
// 실제 프로젝트에 정의되어 있다고 가정합니다.

namespace EDR
{
	namespace Session
	{
		namespace Process
		{
			// --- Helper Functions (Static) ---

			/**
			 * @brief 주어진 노드에서 시작하여 pid와 일치하는 노드를 재귀적으로 탐색합니다.
			 * @param node 탐색을 시작할 노드
			 * @param pid 찾고자 하는 프로세스 ID
			 * @return 찾은 노드의 포인터. 찾지 못하면 nullptr.
			 */
			static Session_node* findNode(struct Session_node& node, HANDLE pid)
			{
				if (node.pid == pid)
				{
					return &node;
				}

				for (auto& child : node.Child)
				{
					if (auto result = findNode(child, pid))
					{
						return result;
					}
				}
				return nullptr;
			}

			/**
			 * @brief 전체 루트 노드들에서 pid와 일치하는 노드를 탐색합니다.
			 * @param roots 탐색 대상인 루트 노드 벡터
			 * @param pid 찾고자 하는 프로세스 ID
			 * @return 찾은 노드의 포인터. 찾지 못하면 nullptr.
			 */
			static Session_node* findNodeInRoots(std::vector<struct Session_node>& roots, HANDLE pid)
			{
				for (auto& root : roots)
				{
					if (auto result = findNode(root, pid))
					{
						return result;
					}
				}
				return nullptr;
			}

			// --- ProcessSession Class Implementation ---

			bool ProcessSession::ProcessCreate(HANDLE pid, HANDLE ppid, std::string& out_processSession)
			{
				// 타임스탬프를 기반으로 고유한 세션 ID 생성
				// 참고: 실제 구현에서는 Util 클래스가 필요합니다. 여기서는 예시로 문자열을 조합합니다.
				uint64_t timestamp = 0;
				EDR::Util::timestamp::Get_Real_Timestamp(&timestamp);
				//std::cout << "timestamp (nano): " << timestamp << std::endl;
				std::string timestamp_str = EDR::Util::timestamp::Timestamp_From_Nano(timestamp);
				//std::cout << "timestamp (str): " << timestamp_str << std::endl;
				std::string sessionId = EDR::Util::hash::sha256FromString(timestamp_str);
				//std::cout << "timestamp: " << timestamp_str << ", sessionId: " << sessionId << std::endl;
				out_processSession = sessionId;

				// 새 프로세스 노드 생성
				Session_node newNode{ sessionId, pid, true, {} };

				// 부모가 없는 최상위 프로세스인 경우
				if (ppid == (HANDLE)0 || ppid == (HANDLE)4) // 시스템 프로세스 등 루트로 간주
				{
					this->Root.push_back(newNode);
					return true;
				}

				// 부모 노드 탐색
				Session_node* parent = findNodeInRoots(this->Root, ppid);
				if (parent)
				{
					// 부모 노드를 찾았으면 자식으로 추가
					parent->Child.push_back(newNode);
					return true;
				}
				else
				{
					// 부모 노드를 찾지 못한 경우 (이벤트 순서가 꼬인 경우 등)
					// 임시 부모 노드를 생성하여 트리의 연결성을 유지
					std::string parentSession = "temp_parent_for_" + std::to_string((unsigned long long)pid);
					parentSession = EDR::Util::hash::sha256FromString(parentSession); // 임시 세션ID

					// 부모는 아직 생성 이벤트가 도착하지 않았으므로 is_alive = false
					Session_node placeholderParentNode{ parentSession, ppid, false, {} };

					// 실제 생성된 노드를 임시 부모의 자식으로 추가
					placeholderParentNode.Child.push_back(newNode);

					// 임시 부모 노드를 루트에 추가
					this->Root.push_back(placeholderParentNode);
					return true;
				}
			}

			bool ProcessSession::AppendingEvent(HANDLE pid, std::string& out_processSession)
			{
				Session_node* node = findNodeInRoots(this->Root, pid);
				if (node)
				{
					out_processSession = node->SesssionID;
					return true;
				}

				// 노드를 찾지 못함
				return false;
			}

			// --- ProcessRemove Helper Functions (Static) ---

			/**
			 * @brief 해당 노드와 모든 자식 노드가 'is_alive == false'인지 재귀적으로 확인합니다.
			 *        노드 제거(가지치기) 가능 여부를 판단하는 데 사용됩니다.
			 * @param node 확인할 노드
			 * @return 제거 가능하면 true, 아니면 false.
			 */
			static bool canBePruned(const Session_node& node)
			{
				// 현재 노드가 살아있으면 제거 불가
				if (node.is_alive)
				{
					return false;
				}

				// 모든 자식 노드에 대해 재귀적으로 확인
				for (const auto& child : node.Child)
				{
					if (!canBePruned(child))
					{
						return false; // 하나라도 살아있는 자손이 있으면 제거 불가
					}
				}

				// 현재 노드도 죽었고, 모든 자손들도 제거 가능하다면, 이 노드는 제거 가능
				return true;
			}

			/**
			 * @brief 특정 벡터(자식 리스트)에서 pid를 가진 노드를 찾아 제거를 시도합니다.
			 *        제거는 canBePruned 조건이 만족될 때만 수행됩니다.
			 * @param nodes 노드 벡터 (주로 부모의 Child 벡터)
			 * @param parentNode 현재 nodes 벡터의 부모 노드 (재귀 호출을 위해)
			 */
			static void attemptToPrune(std::vector<Session_node>& nodes)
			{
				// std::remove_if와 erase를 함께 사용하여 제거 가능한 노드를 한 번에 삭제
				nodes.erase(
					std::remove_if(nodes.begin(), nodes.end(), [](const Session_node& node) {
						return canBePruned(node);
						}),
					nodes.end()
				);

				// 남은 자식들에 대해서도 재귀적으로 가지치기 시도
				for (auto& node : nodes)
				{
					attemptToPrune(node.Child);
				}
			}


			bool ProcessSession::ProcessRemove(HANDLE pid, std::string& out_processSession)
			{
				Session_node* node = findNodeInRoots(this->Root, pid);
				if (!node)
				{
					// 이미 제거되었거나 존재하지 않는 프로세스
					return false;
				}

				// 세션 ID를 출력하고, 'is_alive' 상태를 false로 변경
				out_processSession = node->SesssionID;
				node->is_alive = false;

				// 트리 전체에 대해 가지치기(pruning)를 시도
				// is_alive가 false이고 모든 자식도 제거 가능한 노드들을 정리sha256FromString
				attemptToPrune(this->Root);

				return true;
			}
		}
	}
}