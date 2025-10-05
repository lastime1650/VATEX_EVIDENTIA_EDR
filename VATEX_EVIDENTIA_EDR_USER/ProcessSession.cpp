#include "ProcessSession.hpp"
#include <algorithm> // std::find_if, std::remove_if ����� ���� ����
#include <string>    // std::to_string ���

// ����: EDR::Util ���ӽ����̽��� timestamp �� hash �Լ��� ���ǵǾ� ����.
// #include "Util.hpp"

namespace EDR
{
	namespace Session
	{
		namespace Process
		{
			// --- Helper Functions and Structs (Static) ---

			/**
			 * @brief ��� Ž�� ����� ��� ����ü.
			 *        ã�� ���, �θ� ���, ��Ʈ ����� �����͸� �����մϴ�.
			 */
			struct NodeContext
			{
				Session_node* found = nullptr;
				Session_node* parent = nullptr;
				Session_node* root = nullptr;
			};

			/**
			 * @brief �־��� ��忡�� �����Ͽ� pid�� ��ġ�ϴ� ��带 ��������� Ž���ϰ�,
			 *        �� ����� ���ؽ�Ʈ(�θ�, ��Ʈ)�� ��ȯ�մϴ�.
			 * @param currentNode Ž���� ������ ���� ���
			 * @param parentNode ���� ����� �θ� ���
			 * @param rootNode ���� Ʈ���� ��Ʈ ���
			 * @param pid ã���� �ϴ� ���μ��� ID
			 * @return ã�� ����� ���ؽ�Ʈ ������ ��� NodeContext ����ü.
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
				return {}; // ã�� ����
			}

			/**
			 * @brief ��ü ��Ʈ ���鿡�� pid�� ��ġ�ϴ� ���� �� ���ؽ�Ʈ�� Ž���մϴ�.
			 * @param roots Ž�� ����� ��Ʈ ��� ����
			 * @param pid ã���� �ϴ� ���μ��� ID
			 * @return ã�� ����� ���ؽ�Ʈ. ã�� ���ϸ� ����ִ� NodeContext.
			 */
			static NodeContext findNodeWithContext(std::vector<struct Session_node>& roots, HANDLE pid)
			{
				for (auto& root : roots)
				{
					// ��Ʈ ����� �θ�� nullptr �Դϴ�.
					NodeContext result = findNodeRecursive(root, nullptr, root, pid);
					if (result.found)
					{
						return result;
					}
				}
				return {}; // ��� ��Ʈ���� ã�� ����
			}


			// --- ProcessSession Class Implementation ---

			bool ProcessSession::ProcessCreate(HANDLE pid, HANDLE ppid, std::string& out_processSession, std::string& out_root_processSession, std::string& out_parent_processSession)
			{
				// Ÿ�ӽ������� ������� ������ ���� ID ����
				uint64_t timestamp = 0;
				EDR::Util::timestamp::Get_Real_Timestamp(&timestamp);
				std::string timestamp_str = EDR::Util::timestamp::Timestamp_From_Nano(timestamp);
				std::string sessionId = EDR::Util::hash::sha256FromString(timestamp_str);

				out_processSession = sessionId;

				// �� ���μ��� ��� ����
				Session_node newNode{ sessionId, pid, true, {} };

				// �θ� ���� �ֻ��� ���μ����� ��� (e.g. System Process)
				if (ppid == (HANDLE)0 || ppid == (HANDLE)4)
				{
					out_root_processSession = sessionId;   // �ڱ� �ڽ��� ��Ʈ
					out_parent_processSession = sessionId; // �θ� �����Ƿ� �ڱ� �ڽ��� �θ� �������� ����
					this->Root.push_back(newNode);
					return true;
				}

				// �θ� ��� Ž��
				NodeContext parentContext = findNodeWithContext(this->Root, ppid);
				if (parentContext.found)
				{
					// �θ� ��带 ã������ �ڽ����� �߰�
					out_root_processSession = parentContext.root->SesssionID;
					out_parent_processSession = parentContext.found->SesssionID;
					parentContext.found->Child.push_back(newNode);
					return true;
				}
				else
				{
					// �θ� ��带 ã�� ���� ��� (�̺�Ʈ ������ ���� ��� ��)
					// �ӽ� �θ� ��带 �����Ͽ� Ʈ���� ���Ἲ�� ����
					std::string parentSession = "temp_parent_for_" + out_processSession;
					parentSession = EDR::Util::hash::sha256FromString(parentSession); // �ӽ� ����ID

					// �θ���
					Session_node placeholderParentNode{ parentSession, ppid, true, {} };

					// ���� ������ ��带 �ӽ� �θ��� �ڽ����� �߰�
					placeholderParentNode.Child.push_back(newNode);

					// ���� ������ ����� ���忡�� �θ�� ��Ʈ�� �� �ӽ� ��尡 ��
					out_root_processSession = parentSession;
					out_parent_processSession = parentSession;

					// �ӽ� �θ� ��带 ���ο� ��Ʈ�� �߰�
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
					// �θ� ������ �θ� ����ID, ������(��Ʈ�̸�) �ڱ� �ڽ� ����ID
					out_parent_processSession = context.parent ? context.parent->SesssionID : context.found->SesssionID;
					return true;
				}

				// ��带 ã�� ����
				return false;
			}

			// --- ProcessRemove Helper Functions (Static) ---

			/**
			 * @brief �ش� ���� ��� �ڽ� ��尡 'is_alive == false'���� ��������� Ȯ���մϴ�.
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
			 * @brief ���Ϳ��� ���� ������ ������ ��������� ����(����ġ��)�մϴ�.
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
					// �̹� ���ŵǾ��ų� �������� �ʴ� ���μ���
					return false;
				}

				// ���� ID���� ���
				out_processSession = context.found->SesssionID;
				out_root_processSession = context.root->SesssionID;
				out_parent_processSession = context.parent ? context.parent->SesssionID : context.found->SesssionID;

				// 'is_alive' ���¸� false�� ����
				context.found->is_alive = false;

				// Ʈ�� ��ü�� ���� ����ġ��(pruning)�� �õ�
				attemptToPrune(this->Root);

				return true;
			}
		}
	}
}