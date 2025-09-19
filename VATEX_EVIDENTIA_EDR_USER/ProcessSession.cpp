#include "ProcessSession.hpp"

#include "ProcessSession.hpp"
#include <algorithm> // std::find_if, std::remove_if ����� ���� ����

// ����: behavior_tree.hpp�� Util �Լ����� �ʿ��մϴ�.
// EDR::Util::timestamp ���ӽ����̽��� EDR::Util::hash ���ӽ����̽���
// ���� ������Ʈ�� ���ǵǾ� �ִٰ� �����մϴ�.

namespace EDR
{
	namespace Session
	{
		namespace Process
		{
			// --- Helper Functions (Static) ---

			/**
			 * @brief �־��� ��忡�� �����Ͽ� pid�� ��ġ�ϴ� ��带 ��������� Ž���մϴ�.
			 * @param node Ž���� ������ ���
			 * @param pid ã���� �ϴ� ���μ��� ID
			 * @return ã�� ����� ������. ã�� ���ϸ� nullptr.
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
			 * @brief ��ü ��Ʈ ���鿡�� pid�� ��ġ�ϴ� ��带 Ž���մϴ�.
			 * @param roots Ž�� ����� ��Ʈ ��� ����
			 * @param pid ã���� �ϴ� ���μ��� ID
			 * @return ã�� ����� ������. ã�� ���ϸ� nullptr.
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
				// Ÿ�ӽ������� ������� ������ ���� ID ����
				// ����: ���� ���������� Util Ŭ������ �ʿ��մϴ�. ���⼭�� ���÷� ���ڿ��� �����մϴ�.
				uint64_t timestamp = 0;
				EDR::Util::timestamp::Get_Real_Timestamp(&timestamp);
				//std::cout << "timestamp (nano): " << timestamp << std::endl;
				std::string timestamp_str = EDR::Util::timestamp::Timestamp_From_Nano(timestamp);
				//std::cout << "timestamp (str): " << timestamp_str << std::endl;
				std::string sessionId = EDR::Util::hash::sha256FromString(timestamp_str);
				//std::cout << "timestamp: " << timestamp_str << ", sessionId: " << sessionId << std::endl;
				out_processSession = sessionId;

				// �� ���μ��� ��� ����
				Session_node newNode{ sessionId, pid, true, {} };

				// �θ� ���� �ֻ��� ���μ����� ���
				if (ppid == (HANDLE)0 || ppid == (HANDLE)4) // �ý��� ���μ��� �� ��Ʈ�� ����
				{
					this->Root.push_back(newNode);
					return true;
				}

				// �θ� ��� Ž��
				Session_node* parent = findNodeInRoots(this->Root, ppid);
				if (parent)
				{
					// �θ� ��带 ã������ �ڽ����� �߰�
					parent->Child.push_back(newNode);
					return true;
				}
				else
				{
					// �θ� ��带 ã�� ���� ��� (�̺�Ʈ ������ ���� ��� ��)
					// �ӽ� �θ� ��带 �����Ͽ� Ʈ���� ���Ἲ�� ����
					std::string parentSession = "temp_parent_for_" + std::to_string((unsigned long long)pid);
					parentSession = EDR::Util::hash::sha256FromString(parentSession); // �ӽ� ����ID

					// �θ�� ���� ���� �̺�Ʈ�� �������� �ʾ����Ƿ� is_alive = false
					Session_node placeholderParentNode{ parentSession, ppid, false, {} };

					// ���� ������ ��带 �ӽ� �θ��� �ڽ����� �߰�
					placeholderParentNode.Child.push_back(newNode);

					// �ӽ� �θ� ��带 ��Ʈ�� �߰�
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

				// ��带 ã�� ����
				return false;
			}

			// --- ProcessRemove Helper Functions (Static) ---

			/**
			 * @brief �ش� ���� ��� �ڽ� ��尡 'is_alive == false'���� ��������� Ȯ���մϴ�.
			 *        ��� ����(����ġ��) ���� ���θ� �Ǵ��ϴ� �� ���˴ϴ�.
			 * @param node Ȯ���� ���
			 * @return ���� �����ϸ� true, �ƴϸ� false.
			 */
			static bool canBePruned(const Session_node& node)
			{
				// ���� ��尡 ��������� ���� �Ұ�
				if (node.is_alive)
				{
					return false;
				}

				// ��� �ڽ� ��忡 ���� ��������� Ȯ��
				for (const auto& child : node.Child)
				{
					if (!canBePruned(child))
					{
						return false; // �ϳ��� ����ִ� �ڼ��� ������ ���� �Ұ�
					}
				}

				// ���� ��嵵 �׾���, ��� �ڼյ鵵 ���� �����ϴٸ�, �� ���� ���� ����
				return true;
			}

			/**
			 * @brief Ư�� ����(�ڽ� ����Ʈ)���� pid�� ���� ��带 ã�� ���Ÿ� �õ��մϴ�.
			 *        ���Ŵ� canBePruned ������ ������ ���� ����˴ϴ�.
			 * @param nodes ��� ���� (�ַ� �θ��� Child ����)
			 * @param parentNode ���� nodes ������ �θ� ��� (��� ȣ���� ����)
			 */
			static void attemptToPrune(std::vector<Session_node>& nodes)
			{
				// std::remove_if�� erase�� �Բ� ����Ͽ� ���� ������ ��带 �� ���� ����
				nodes.erase(
					std::remove_if(nodes.begin(), nodes.end(), [](const Session_node& node) {
						return canBePruned(node);
						}),
					nodes.end()
				);

				// ���� �ڽĵ鿡 ���ؼ��� ��������� ����ġ�� �õ�
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
					// �̹� ���ŵǾ��ų� �������� �ʴ� ���μ���
					return false;
				}

				// ���� ID�� ����ϰ�, 'is_alive' ���¸� false�� ����
				out_processSession = node->SesssionID;
				node->is_alive = false;

				// Ʈ�� ��ü�� ���� ����ġ��(pruning)�� �õ�
				// is_alive�� false�̰� ��� �ڽĵ� ���� ������ ������ ����sha256FromString
				attemptToPrune(this->Root);

				return true;
			}
		}
	}
}