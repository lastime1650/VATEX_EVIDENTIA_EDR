#ifndef IAM_CLIENT_HPP
#define IAM_CLIENT_HPP

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
#include <fstream>
#include <sstream> // stringstream을 사용하기 위해 필요

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include "json.hpp"

namespace EDR
{
	namespace Util
	{
		namespace IAM
		{
			namespace Client
			{
				class IAMClient
				{
				public:
					IAMClient(
						std::string IAM_SERVER_IP,
						unsigned int IAM_SERVER_PORT
					) : IAM_SERVER_IP(IAM_SERVER_IP),
						IAM_SERVER_PORT(IAM_SERVER_PORT)
					{}
					~IAMClient() = default;

					// IAM 서버로부터 토큰 발급
					std::string SendLoginInfo(
						std::string user_id,
						std::string user_password,
						std::string username
					) {
						httplib::SSLClient cli(IAM_SERVER_IP.c_str(), IAM_SERVER_PORT);
						cli.enable_server_certificate_verification(false); // (restapi서버가 내부적으로 자체 서명을 하므로 클라이언트단의 인증을 비활성)

						cli.set_read_timeout(5, 0); // 5초
						cli.set_write_timeout(5, 0); // 5초

						nlohmann::json login_json;
						login_json["userid"] = user_id;
						login_json["userpw"] = user_password;
						login_json["username"] = username;

						auto res = cli.Post("/api/solution/iam/add/user", login_json.dump(), "application/json");
						if (res && res->status == 200) {
							nlohmann::json response_json = nlohmann::json::parse(res->body);
							if (response_json.contains("token")) {
								return response_json["token"].get<std::string>();
							}
							else {
								throw std::runtime_error("IAM server response does not contain token.");
							}
						}
						else {
							throw std::runtime_error("Failed to connect to IAM server or invalid response.");
						}
					}
				private:
					std::string IAM_SERVER_IP;
					unsigned int IAM_SERVER_PORT;
				};
			}
		}
	}
}


#endif