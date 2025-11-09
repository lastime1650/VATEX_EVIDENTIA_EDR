#ifndef VATEX_INTELLINA_INTELLIGENCE_HPP
#define VATEX_INTELLINA_INTELLIGENCE_HPP

#include <fmt/format.h>
#include "../httplib.h"
#include "../json.hpp"
using namespace nlohmann;

namespace EDR
{
    namespace Util
    {
        namespace Intelligence
        {
            enum VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum
            {
                Query_NETWORK_IPV4 = 1,
                Query_NETWORK_IPV4_with_PORT,
                Query_FILE_SHA256

            };
            struct VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Platform
            {
                std::string ModuleName;
                std::vector<json> output;
            };
            struct VATEX_INTELLINA_INTELLIGENCE__RESPONSE
            {
                bool is_success;
 
                std::map< VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum, std::vector<VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Platform> > outputs; // if "is_success" == false, empty
            };

            std::string QueryEnum_to_String(const VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum enumvalue)
            {
                switch (enumvalue)
                {
                    case VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum::Query_FILE_SHA256:
                        return "file-sha256";
                    case VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum::Query_NETWORK_IPV4:
                        return "network-only-ipv4";
                    case VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum::Query_NETWORK_IPV4_with_PORT:
                        return "network-ipv4-port";   
                    default:
                    {
                        throw std::runtime_error("??? at Enum_to_String");
                    }
                }
            }

            class VATEX_INTELLINA_INTELLIGENCE
            {
                public:
                    VATEX_INTELLINA_INTELLIGENCE(
                        std::string server_ip = "127.0.0.1", // same endpoint
                        unsigned int server_port = 51034
                    ): Requester(server_ip, server_port)
                    {}
                    ~VATEX_INTELLINA_INTELLIGENCE() = default;

                    // 0. STATUS ( server api check )
                    
                    // 1. NETWORK_IPV4
                    std::optional< VATEX_INTELLINA_INTELLIGENCE__RESPONSE > Query_NETWORK_IPV4(std::string Ipv4)
                    {

                        std::string Path = fmt::format(R"(/network/ipv4?Ipv4={})", Ipv4);
                        auto response = Requester.Get(
                            Path
                        );
                        if (!response) {
                            // 서버 접속 실패
                            throw std::runtime_error("Failed to connect to server or server is down.");
                        }

                        if ( response->status != 200 )
                            return std::nullopt;
                        
                        return _get_response(  VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum::Query_NETWORK_IPV4, response->body);
                    }

                    // 2. NETWORK_IPV4_PORT
                    std::optional< VATEX_INTELLINA_INTELLIGENCE__RESPONSE > Query_NETWORK_IPV4_with_PORT(std::string Ipv4, unsigned int Port)
                    {
                        std::string Path = fmt::format(R"(/network/ipv4port?Ipv4={}&Port={})", Ipv4, Port);
                        auto response = Requester.Get(
                            Path
                        );
                        if (!response) {
                            // 서버 접속 실패
                            throw std::runtime_error("Failed to connect to server or server is down.");
                        }

                        if ( response->status != 200 )
                            return std::nullopt;
                        
                        return _get_response( VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum::Query_NETWORK_IPV4_with_PORT, response->body);
                    }
                    
                    // 3. FILE_SHA256
                    std::optional< VATEX_INTELLINA_INTELLIGENCE__RESPONSE > Query_FILE_SHA256(std::string SHA256)
                    {
                        std::string Path = fmt::format(R"(/file/sha256?Sha256={})", SHA256);
                        auto response = Requester.Get(
                            Path
                        );
                        if (!response) {
                            // 서버 접속 실패
                            throw std::runtime_error("Failed to connect to server or server is down.");
                        }

                        if ( response->status != 200 )
                            return std::nullopt;
                        
                        return _get_response(VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum::Query_FILE_SHA256, response->body);
                    }
                    
                    // 4. FILE_Binary
                    // 5. EMAIL

                    
                    

                    std::optional<json> RESPONSE_to_Json( const VATEX_INTELLINA_INTELLIGENCE__RESPONSE& input_Response_struct )
                    {
                        /*
                            {
                                "NETWORK_IPV4": [
                                    {"threatfox": [...]},
                                    {"otx": [...]},
                                ]
                            }
                        */
                        auto output_json = json::object();

                        // map
                        for(const auto& [key, value] : input_Response_struct.outputs)
                        {

                            std::string Query_Type_str;
                            switch (key)
                            {
                                case VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum::Query_NETWORK_IPV4:
                                {
                                    Query_Type_str = "NETWORK_IPV4";
                                    break;
                                }
                                case VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum::Query_NETWORK_IPV4_with_PORT:
                                {
                                    Query_Type_str = "NETWORK_IPV4_with_PORT";
                                    break;
                                }
                                case VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum::Query_FILE_SHA256:
                                {
                                    Query_Type_str = "FILE_SHA256";
                                    break;
                                }
                                default:
                                    return std::nullopt;
                            }
                            
                            // arry
                            auto Modules = json::array();
                            for(const auto& module : value)
                            {
                                Modules.push_back(
                                    {
                                        {module.ModuleName, module.output}
                                    }
                                );
                            }

                            output_json[Query_Type_str] = Modules;
                        }
                        return output_json;
                    }

                private:
                    httplib::Client Requester;

                    
                    std::optional< VATEX_INTELLINA_INTELLIGENCE__RESPONSE > _get_response( const VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Query_Enum& QueryEnum, std::string& body)
                    {
                        auto Body = json::parse( body );

                        if(Body.is_string())
                        {
                            Body = json::parse(Body.get<std::string>()); // 한번더 Json객체 인식시켜야함.
                        }

                        
                        if(!Body.contains("is_success"))
                            return std::nullopt;
                        
                        auto ResponseObj = VATEX_INTELLINA_INTELLIGENCE__RESPONSE();

                        if( Body["is_success"].get<bool>() )
                        {
                            // 응답성공
                            ResponseObj.is_success = true;

                            // 응답된 것을 추가 (null일 수 있음 값이)
                            /*
                                example>>>>>>>>>
                                "result": {
                                    "threatfox": [{...},{...},,,],
                                    "otx": null, 
                                    ....
                                }
                            */

                            ResponseObj.outputs[QueryEnum] = std::vector<VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Platform>();

                            if(Body.contains("result"))
                            {

                                // 모두 null이면 std::nullopt반환 (아예실패로)

                                bool is_break = false;
                                for (const auto& [ModuleName, ModuleResults] : Body["result"].items()) {
                                    if(!ModuleResults.is_null())
                                    {
                                        is_break = true;
                                        break;
                                    }
                                }
                                if(!is_break)// break 발생이 없었다면 모두 null임 
                                    return std::nullopt; 




                                // 반환값을 구조체로 변환하여 리턴 
                                for (const auto& [ModuleName, ModuleResults] : Body["result"].items()) {

                                    if(ModuleResults.is_null())
                                        continue;
                                        
                                    std::vector<json> array_results;

                                    if (ModuleResults.is_array()) {
                                        // ModuleResults 배열을 std::vector<json>으로 바로 복사
                                        array_results = ModuleResults.get<json::array_t>();
                                    }

                                    ResponseObj.outputs[QueryEnum].push_back(
                                        VATEX_INTELLINA_INTELLIGENCE__RESPONSE_Platform{
                                            .ModuleName = ModuleName,
                                            .output = array_results
                                        }
                                    );
                                }


                            }

                        }
                        else
                        {
                            // 응답실패
                            ResponseObj.is_success = false;
                        }

                        return ResponseObj;
                    }
            };
        }
    }
}


#endif