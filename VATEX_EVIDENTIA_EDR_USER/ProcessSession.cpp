#include "ProcessSession.hpp"
#include <algorithm> // std::find_if, std::remove_if 사용을 위해 포함
#include <string>    // std::to_string 사용

// 가정: EDR::Util 네임스페이스에 timestamp 및 hash 함수가 정의되어 있음.
// #include "Util.hpp"

namespace EDR
{
	namespace Session
	{
		namespace Process
		{
			// --- Helper Functions and Structs (Static) ---

			/**
			 * @brief 노드 탐색 결과를 담는 구조체.
			 *        찾은 노드, 부모 노드, 루트 노드의 포인터를 포함합니다.
			 */
			struct NodeContext
			{
				Session_node* found = nullptr;
				Session_node* parent = nullptr;
				Session_node* root = nullptr;
			};

			/**
			 * @brief 주어진 노드에서 시작하여 pid와 일치하는 노드를 재귀적으로 탐색하고,
			 *        그 노드의 컨텍스트(부모, 루트)를 반환합니다.
			 * @param currentNode 탐색을 시작할 현재 노드
			 * @param parentNode 현재 노드의 부모 노드
			 * @param rootNode 현재 트리의 루트 노드
			 * @param pid 찾고자 하는 프로세스 ID
			 * @return 찾은 노드의 컨텍스트 정보가 담긴 NodeContext 구조체.
			 */
			static NodeContext findNodeRecursive(Session_node& currentNode, Session_node* parentNode, Session_node& rootNode, HANDLE pid)
			{
				if (currentNode.pid == pid && currentNode.is_alive)
				{
					return { &currentNode, parentNode, &rootNode };
				}

				for (auto& child : currentNode.Child)
				{
					NodeContext result = findNodeRecursive(child, &currentNode, rootNode, pid);
					if (result.found)
					{
						return result;
					}
				}
				return {}; // 찾지 못함
			}

			/**
			 * @brief 전체 루트 노드들에서 pid와 일치하는 노드와 그 컨텍스트를 탐색합니다.
			 * @param roots 탐색 대상인 루트 노드 벡터
			 * @param pid 찾고자 하는 프로세스 ID
			 * @return 찾은 노드의 컨텍스트. 찾지 못하면 비어있는 NodeContext.
			 */
			static NodeContext findNodeWithContext(std::vector<struct Session_node>& roots, HANDLE pid)
			{
				for (auto& root : roots)
				{
					// 루트 노드의 부모는 nullptr 입니다.
					NodeContext result = findNodeRecursive(root, nullptr, root, pid);
					if (result.found)
					{
						return result;
					}
				}
				return {}; // 모든 루트에서 찾지 못함
			}


			// --- ProcessSession Class Implementation ---

			bool ProcessSession::ProcessCreate(HANDLE pid, HANDLE ppid, std::string& out_processSession, std::string& out_root_processSession, std::string& out_parent_processSession)
			{
				// 타임스탬프를 기반으로 고유한 세션 ID 생성
				uint64_t timestamp = 0;
				EDR::Util::timestamp::Get_Real_Timestamp(&timestamp);
				std::string timestamp_str = EDR::Util::timestamp::Timestamp_From_Nano(timestamp);
				std::string sessionId = EDR::Util::hash::sha256FromString(timestamp_str);

				out_processSession = sessionId;

				// 새 프로세스 노드 생성
				Session_node newNode{ sessionId, pid, true, {} };

				// 부모가 없는 최상위 프로세스인 경우 (e.g. System Process)
				if (ppid == (HANDLE)0 || ppid == (HANDLE)4)
				{
					out_root_processSession = sessionId;   // 자기 자신이 루트
					out_parent_processSession = sessionId; // 부모가 없으므로 자기 자신을 부모 세션으로 설정
					this->Root.push_back(newNode);
					return true;
				}

				// 부모 노드 탐색
				NodeContext parentContext = findNodeWithContext(this->Root, ppid);
				if (parentContext.found)
				{
					// 부모 노드를 찾았으면 자식으로 추가
					out_root_processSession = parentContext.root->SesssionID;
					out_parent_processSession = parentContext.found->SesssionID;
					parentContext.found->Child.push_back(newNode);
					return true;
				}
				else
				{
					// 부모 노드를 찾지 못한 경우 (이벤트 순서가 꼬인 경우 등)
					// 임시 부모 노드를 생성하여 트리의 연결성을 유지
					std::string parentSession = "temp_parent_for_" + out_processSession;
					parentSession = EDR::Util::hash::sha256FromString(parentSession); // 임시 세션ID

					// 부모노드
					Session_node placeholderParentNode{ parentSession, ppid, true, {} };

					// 실제 생성된 노드를 임시 부모의 자식으로 추가
					placeholderParentNode.Child.push_back(newNode);

					// 새로 생성된 노드의 입장에서 부모와 루트는 이 임시 노드가 됨
					out_root_processSession = parentSession;
					out_parent_processSession = parentSession;

					// 임시 부모 노드를 새로운 루트로 추가
					this->Root.push_back(placeholderParentNode);
					return true;
				}
			}

			bool ProcessSession::AppendingEvent(HANDLE pid, std::string& out_processSession, std::string& out_root_processSession, std::string& out_parent_processSession)
			{
				NodeContext context = findNodeWithContext(this->Root, pid);
				if (context.found)
				{
					out_processSession = context.found->SesssionID;
					out_root_processSession = context.root->SesssionID;
					// 부모가 있으면 부모 세션ID, 없으면(루트이면) 자기 자신 세션ID
					out_parent_processSession = context.parent ? context.parent->SesssionID : context.found->SesssionID;
					return true;
				}

				// 노드를 찾지 못함
				return false;
			}

			// --- ProcessRemove Helper Functions (Static) ---

			/**
			 * @brief 해당 노드와 모든 자식 노드가 'is_alive == false'인지 재귀적으로 확인합니다.
			 */
			static bool canBePruned(const Session_node& node)
			{
				if (node.is_alive)
				{
					return false;
				}
				for (const auto& child : node.Child)
				{
					if (!canBePruned(child))
					{
						return false;
					}
				}
				return true;
			}

			/**
			 * @brief 벡터에서 제거 가능한 노드들을 재귀적으로 정리(가지치기)합니다.
			 */
			static void attemptToPrune(std::vector<Session_node>& nodes)
			{
				nodes.erase(
					std::remove_if(nodes.begin(), nodes.end(), [](const Session_node& node) {
						return canBePruned(node);
						}),
					nodes.end()
				);

				for (auto& node : nodes)
				{
					attemptToPrune(node.Child);
				}
			}

			bool ProcessSession::ProcessRemove(HANDLE pid, std::string& out_processSession, std::string& out_root_processSession, std::string& out_parent_processSession)
			{
				NodeContext context = findNodeWithContext(this->Root, pid);
				if (!context.found)
				{
					// 이미 제거되었거나 존재하지 않는 프로세스
					return false;
				}

				// 세션 ID들을 출력
				out_processSession = context.found->SesssionID;
				out_root_processSession = context.root->SesssionID;
				out_parent_processSession = context.parent ? context.parent->SesssionID : context.found->SesssionID;

				// 'is_alive' 상태를 false로 변경
				context.found->is_alive = false;

				// 트리 전체에 대해 가지치기(pruning)를 시도
				attemptToPrune(this->Root);

				return true;
			}
		}
	}
}