#ifndef VATEX_SPIENTIA_SIEM_HPP
#define VATEX_SPIENTIA_SIEM_HPP

#include <fmt/format.h>
#include "../httplib.h"
#include "../json.hpp"
#include "../Timestamp/timestamp.hpp"

namespace EDR
{
    namespace Util
    {
        namespace ToSiem
        {

            namespace Security_Event
            {

                // 위협 또는 보안 이벤트 발생 메이커 추적
                enum Event_detected_method
                {
                    rule,
                    machine_learning,
                    deep_learning,
                    intelligence
                };

                // 위협 또는 보안 이벤트 카테고리 (광범위)
                enum Event_Topic
                {

                };

                enum Platform
                {
                    edr,
                    ndr
                };

                enum Severity
                {
                    info=1,
                    low,
                    medium,
                    high,
                    critical
                };
            }

            constexpr char* Security_Threat_URL = "/api/solution/siem/event/push/security-threat";
            constexpr char* RAW_EDR_URL = "/api/solution/siem/event/push/raw-edr";
            //constexpr char* RAW_NDR_URL = "/api/solution/siem/event/push/raw-ndr";

            class SiemClient
            {
                public:
                    SiemClient(
                        std::string server_ip = "127.0.0.1", // same endpoint
                        unsigned int server_port = 10302
                    ): Requester(server_ip, server_port)
                    {}
                    ~SiemClient() = default;

                    // 1. 보안 이벤트 ( EDR: Intelligence, Rule, ML 3가지의 정규화된 SIEM 결과 전달.)
                    bool Send_Security_Event(
                        const std::string& sender_platform,           // 이벤트 전송한 플랫폼 
                        const std::string& severity,                  // 심각도
                        const std::string& description,                     // 이벤트 이유
                        const std::string& response_description,             // 오탐 방지용 예외형 문구
                        const std::string& category,                // 이벤트 카테고리


                        const std::string& detected_method,         // 이벤트 탐지 방법/원인 경로
                        const unsigned long long& timestamp_nano    // 당시 타임스탬프
                    )
                    {
                        nlohmann::json PushEvent = {
                            {"platform", sender_platform },
                            {"description", description },
                            {"detected_method", detected_method },
                            {"response_description", response_description },
                            {"severity", severity },
                            {"category", category},
                            
                            {"timestamp_nano", timestamp_nano },
                            {"timestamp_nano_iso8601", EDR::Util::timestamp::To_Nano_Iso8601(timestamp_nano) }
                        };
                        return _sendPost(Security_Threat_URL, PushEvent);
                    }

                private:
                    std::string server_ip;
                    unsigned int server_port;

                    httplib::Client Requester;


                    // send post
                    template <typename T>
                    bool _sendPost(const std::string& Path, const T& body)
                    {
                        std::string BODY;
                        if constexpr( std::is_same_v<T, nlohmann::json> )
                        {
                            BODY = body.dump();
                        }
                        else if constexpr( std::is_same_v<T, std::string> )
                        {
                            BODY = body;
                        }

                        auto response = Requester.Post(
                            Path,
                            BODY,
                            "application/json"
                        );

                        if(!response || response->status != 200)
                            return false;
                        


                        return true;
                    }
            };
        }
    }
}

#endif