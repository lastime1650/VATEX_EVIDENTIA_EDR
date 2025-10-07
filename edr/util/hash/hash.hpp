#ifndef HASH_HPP
#define HASH_HPP

#define _CRT_SECURE_NO_WARNINGS
#define OPENSSL_SUPPRESS_DEPRECATED // OpenSSL 3.0+ 에서 사용 중단 경고를 비활성화

#define FMT_UNICODE 0

#undef min
#undef max

#include <algorithm>
#include <openssl/sha.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <type_traits>
#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>
#include <csignal>
#include <cerrno>
#include <cstring>   // strerror
#include <vector>
#include <thread> 
#include <tuple>
#include <unordered_map>
#include <cstdlib>
#include <cstdint>   // uint64_t를 위해
#include <atomic>
#include <fmt/core.h>
#include <fmt/chrono.h>
#include <utility> 
#include <fstream>
#include <iomanip>
#include <sstream> // stringstream을 사용하기 위해 필요

#include <linux/types.h>
#include <linux/errno.h>

namespace EDR
{
	namespace Util
	{
        namespace hash
        {
            constexpr size_t CHUNK_SIZE = 1024ULL * 1024ULL * 1024ULL; // 1GB

            inline std::string sha256FromVector(const std::vector<char>& data)
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

            inline std::string sha256FromU64(__u64& value) {
                // 64비트 값을 바이트 배열로 변환
                unsigned char data[8];
                for (int i = 0; i < 8; ++i) {
                    data[7 - i] = (value >> (i * 8)) & 0xFF;
                }

                // SHA-256 해시 계산
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256(data, sizeof(data), hash);

                // 해시를 16진수 문자열로 변환
                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                    oss << std::setw(2) << static_cast<unsigned int>(hash[i]);
                }

                return oss.str();
            }

            inline std::string sha256FromString(std::string& input) {
                unsigned char hash[SHA256_DIGEST_LENGTH];

                // SHA-256 계산
                SHA256(reinterpret_cast<const unsigned char*>((input).c_str()), (input).size(), hash);

                // 해시를 16진수 문자열로 변환
                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                    oss << std::setw(2) << static_cast<unsigned int>(hash[i]);
                }

                return oss.str();
            }


            template<typename V>
            std::string Get_SHA256(V& value)
            {
                if constexpr (std::is_same_v< V, __u64>)
                {
                    __u64& __u64_p = static_cast<__u64&>(value);
                    return sha256FromU64(__u64_p);
                }
                else if constexpr (std::is_same_v< V, std::string>)
                {
                    std::string& string_p = static_cast<std::string&>(value);
                    return sha256FromString(string_p);
                }
                else if constexpr (std::is_same_v< V, std::vector<char> >)
                {
                    //  Vector에 char형으로 바이너리가 저장된 타입일 때,
                    std::vector<char>& vec = static_cast<std::vector<char>&>(value);
                    return sha256FromVector(vec);
                }
                else
                {
                    throw std::runtime_error("지원하지 않은 SHA256 구하기 함수의 인자 타입");
                    exit(-1);
                }
            }
        }
	}
}

#endif