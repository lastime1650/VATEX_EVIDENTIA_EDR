#include "Hash.hpp"
#include <set>
namespace EDR
{
	namespace Util
	{
        namespace hash
        {
            std::string sha256FromVector(const std::vector<char>& data)
            {

                SHA256_CTX ctx;
                SHA256_Init(&ctx);


                size_t offset = 0;
                size_t totalSize = data.size();

                while (offset < totalSize)
                {
                    size_t bytesToProcess = std::min(CHUNK_SIZE, totalSize - offset);
                    SHA256_Update(&ctx, reinterpret_cast<const unsigned char*>(data.data() + offset), bytesToProcess);
                    offset += bytesToProcess;
                }

                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256_Final(hash, &ctx);

                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                    oss << std::setw(2) << static_cast<unsigned int>(hash[i]);
                }

                return oss.str();
            }

            std::string sha256FromU64(ULONG64& value) {
                // 64��Ʈ ���� ����Ʈ �迭�� ��ȯ
                unsigned char data[8];
                for (int i = 0; i < 8; ++i) {
                    data[7 - i] = (value >> (i * 8)) & 0xFF;
                }

                // SHA-256 �ؽ� ���
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256(data, sizeof(data), hash);

                // �ؽø� 16���� ���ڿ��� ��ȯ
                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                    oss << std::setw(2) << static_cast<unsigned int>(hash[i]);
                }

                return oss.str();
            }

            std::string sha256FromString(std::string& input) {
                unsigned char hash[SHA256_DIGEST_LENGTH];

                // SHA-256 ���
                SHA256(reinterpret_cast<const unsigned char*>((input).c_str()), (input).size(), hash);

                // �ؽø� 16���� ���ڿ��� ��ȯ
                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                    oss << std::setw(2) << static_cast<unsigned int>(hash[i]);
                }

                return oss.str();
            }


        }
	}
}