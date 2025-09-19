#ifndef HASH_HPP
#define HASH_HPP

#define _CRT_SECURE_NO_WARNINGS
#define OPENSSL_SUPPRESS_DEPRECATED // OpenSSL 3.0+ ���� ��� �ߴ� ��� ��Ȱ��ȭ

#define FMT_UNICODE 0

#include <windows.h>
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
#include <cstdint>   // uint64_t�� ����
#include <atomic>
#include <fmt/core.h>
#include <fmt/chrono.h>
#include <utility> 
#include <fstream>
#include <iomanip>
#include <fstream>
#include <sstream> // stringstream�� ����ϱ� ���� �ʿ�

namespace EDR
{
	namespace Util
	{
        namespace hash
        {
            constexpr size_t CHUNK_SIZE = 1024ULL * 1024ULL * 1024ULL; // 1GB

            std::string sha256FromU64(ULONG64& value);
            std::string sha256FromString(std::string& input);
            std::string sha256FromVector(const std::vector<char>& data);


            template<typename V>
            std::string Get_SHA256(V& value)
            {
                if constexpr (std::is_same_v< V, ULONG64>)
                {
                    ULONG64& __u64_p = static_cast<ULONG64&>(value);
                    return sha256FromU64(__u64_p);
                }
                else if constexpr (std::is_same_v< V, std::string>)
                {
                    std::string& string_p = static_cast<std::string&>(value);
                    return sha256FromString(string_p);
                }
                else if constexpr (std::is_same_v< V, std::vector<char> >)
                {
                    //  Vector�� char������ ���̳ʸ��� ����� Ÿ���� ��,
                    std::vector<char>& vec = static_cast<std::vector<char>&>(value);
                    return sha256FromVector(vec);
                }
                else
                {
                    throw std::runtime_error("�������� ���� SHA256 ���ϱ� �Լ��� ���� Ÿ��");
                    exit(-1);
                }
            }
        }
	}
}

#endif