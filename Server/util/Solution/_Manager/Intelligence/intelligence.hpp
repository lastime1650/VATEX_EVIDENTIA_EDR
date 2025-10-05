#ifndef INTELLIGENCE_HPP
#define INTELLIGENCE_HPP

#include "../../../../../util/util.hpp"
#include "../json.hpp"
using namespace nlohmann;
#include "../httplib.h"
#include <iostream>
#include <vector>

namespace Solution
{
    namespace Intelligence
    {
        class Intellina
        {
            public:
                Intellina(
                    std::string API_ServerIP,
                    unsigned int API_ServerPORT = 51034
                ) : API_ServerIP(API_ServerIP), API_ServerPORT(API_ServerPORT), APIClient(API_ServerIP, API_ServerPORT)
                {
                    
                }
                ~Intellina() = default;
                
                bool ConnectionCheck()
                {
                    std::string URL("/status");
                    auto res = APIClient.Get(
                        URL
                    );
                    if(!res || res->status != 200)
                        return false;
                    
                    // 응답 body 검사
                    try {
                        json ResJSON = json::parse(res->body);
                        if (ResJSON.contains("is_success") && ResJSON["is_success"].get<bool>() == true) {
                            return true;
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "JSON parse error: " << e.what() << std::endl;
                        return false;
                    }

                    return false;

                }

                /*
                    Network
                */
                bool Query_network_only_ipv4(std::string ipv4, json& output)
                {
                    std::string URL = "/network/ipv4?Ipv4=" + ipv4;
                    auto res = APIClient.Get(URL);
                    return _post_processing(res, output);
                }

                bool Query_network_ipv4_and_port(std::string ipv4, unsigned int port, json& output)
                {
                    std::string URL = "/network/ipv4port?Ipv4=" + ipv4 + "&Port=" + std::to_string(port);
                    auto res = APIClient.Get(URL);
                    return _post_processing(res, output);
                }

                /*
                    File
                */
                bool Query_file_sha256(std::string sha256, json& output)
                {
                    std::string URL = "/file/sha256?Sha256=" + sha256;
                    auto res = APIClient.Get(URL);
                    return _post_processing(res, output);
                }
                bool Query_file_binary(std::vector<uint8_t>& binary, json& output)
                {
                    std::string URL = "/file/binary";
                    std::string Body = EDR::Util::Base64::base64_encode(binary.data(), binary.size()); // base64
                    auto res = APIClient.Post(URL,Body,"application/json");
                    return _post_processing(res, output);
                }
                bool Query_file_binary(std::string base64_binary, json& output)
                {
                    std::string URL = "/file/binary";
                    std::string Body = base64_binary; // base64
                    auto res = APIClient.Post(URL,Body,"application/json");
                    return _post_processing(res, output);
                }



            private:
                
                std::string API_ServerIP;
                unsigned int API_ServerPORT;

                httplib::Client APIClient;

                bool _post_processing( httplib::Result& input_api_result, json& output_result  )
                {
                    if (!input_api_result || input_api_result->status != 200) return false;

                    try {
                        json ResJSON = json::parse(input_api_result->body);

                        if ( !ResJSON.contains("is_success") || !ResJSON["is_success"].get<bool>() || !ResJSON.contains("result") )
                            return false;
                        
                        output_result = ResJSON["result"];
                        return ResJSON["is_success"].get<bool>();
                    } catch (const std::exception& e) {
                        std::cerr << "JSON parse error: " << e.what() << std::endl;
                        return false;
                    }
                }
        };
    }
}

#endif