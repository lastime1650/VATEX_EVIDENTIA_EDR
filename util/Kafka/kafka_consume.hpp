#ifndef KAFKA_CONSUME_HPP
#define KAFKA_CONSUME_HPP

#include "../Queue/queue.hpp" // EDR::Util::Queue::Queue가 정의된 헤더
#include "../json.hpp"        // nlohmann::json이 정의된 헤더

#include <cppkafka/cppkafka.h>
#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

using namespace nlohmann;

namespace EDR
{
    namespace Util
    {
        namespace Kafka
        {

            struct KAFKA_MESSAGE
            {
                std::string topic_name;
                unsigned long long offset;
                json message;
                std::string original_message;
            };

            class Kafka_Consumer
            {
            public:
                Kafka_Consumer(
                    const std::string& brokers,
                    const std::string& group_id,
                    const std::string& topic) : config_({
                                                   {"metadata.broker.list", brokers},
                                                   {"group.id", group_id},
                                                   // 자동 커밋은 편리하지만, 메시지 처리 실패 시 유실될 수 있습니다.
                                                   // 더 높은 신뢰성이 필요하다면 false로 설정하고 수동 커밋을 고려해야 합니다.
                                                   {"enable.auto.commit", true},
                                                   {"auto.offset.reset", "earliest"}
                                               }),
                                               consumer_(config_),
                                               topic_(topic)
                {
                    /*
                        패턴 문자열은 ^로 시작해야 정규식 기반 매칭으로 인식
                    */
                    consumer_.subscribe({topic_});
                }

                ~Kafka_Consumer()
                {
                    Stop();
                }

                bool Run()
                {
                    if (is_working_thread)
                        return false;

                    is_working_thread = true;
                    loopreceivethread = std::thread(
                        [this]()
                        {
                            while (this->is_working_thread)
                            {
                                // ==========================================================
                                // [수정 1] 블로킹 poll 대신 100ms 타임아웃을 가진 poll을 사용합니다.
                                // 이렇게 하면 메시지가 없을 때도 루프가 멈추지 않고,
                                // is_working_thread 플래그를 주기적으로 확인하며,
                                // 카프카 브로커로 하트비트를 안정적으로 보낼 수 있습니다.
                                // ==========================================================
                                cppkafka::Message msg = consumer_.poll(std::chrono::milliseconds(100));

                                // msg가 false인 경우는 타임아웃일 뿐, 에러가 아닙니다.
                                // 바로 루프의 다음으로 넘어갑니다.
                                if (!msg)
                                {
                                    continue;
                                }

                                // 메시지에 에러가 있는지 확인합니다.
                                if (msg.get_error())
                                {
                                    // EOF(End of Partition)는 실제 에러가 아니므로 무시합니다.
                                    if (!msg.is_eof())
                                    {
                                        // 실제 에러는 로그로 남기는 것이 좋습니다.
                                        std::cerr << "[Kafka Consumer Error] " << msg.get_error() << std::endl;
                                    }
                                    // 에러가 있거나 EOF인 경우, 메시지 처리를 건너뜁니다.
                                    continue;
                                }

                                // 정상적인 메시지 처리
                                std::string topic = msg.get_topic();
                                std::string payload = msg.get_payload();
                                unsigned long long offset = msg.get_offset();


                                // [추가] + 제어문자 제거
                                payload.erase(
                                std::remove_if(payload.begin(), payload.end(),
                                    [](unsigned char c) {
                                        // 0x20(스페이스)보다 작은 ASCII 값은 제어 문자입니다.
                                        return c < 0x20;
                                    }),
                                payload.end());


                                //std::cout << "payload: " << payload;
                                json tojson_message;    
                                try
                                {
                                    tojson_message = json::parse(payload);
                                }
                                catch (json::parse_error &e)
                                {
                                    // JSON 파싱 실패 시 로그를 남기고 해당 메시지는 건너뜁니다.
                                    std::cerr << "[Kafka] Json parse failed: " << e.what() << std::endl;
                                    std::cerr << "[Kafka] Offending message (Offset: " << offset << "): " << payload << std::endl;
                                    continue;
                                }

                                struct KAFKA_MESSAGE MessageObject = {
                                    .topic_name = topic,
                                    .offset = offset,
                                    .message = tojson_message,
                                    .original_message = payload};

                                this->message_queue.put(MessageObject);

                                // ==========================================================
                                // [수정 2] 루프 내의 모든 sleep() 호출을 제거했습니다.
                                // poll()의 타임아웃이 대기 역할을 대신합니다.
                                // ==========================================================
                            }
                        });

                    return true;
                }

                bool Stop()
                {
                    if (!is_working_thread)
                        return false;

                    is_working_thread = false;

                    if (loopreceivethread.joinable())
                        loopreceivethread.join();

                    return true;
                }

                struct KAFKA_MESSAGE get_message_from_queue()
                {
                    return message_queue.get();
                }

            private:
                std::atomic<bool> is_working_thread = false;
                std::thread loopreceivethread;

                cppkafka::Configuration config_;
                cppkafka::Consumer consumer_;
                std::string topic_;

                // [수정 3] 원본 코드에서 사용되지 않던 멤버 변수들을 제거하여 코드를 정리했습니다.
                // std::string Topic;
                // std::string BrokerIp;
                // unsigned int BrokerPort;

                EDR::Util::Queue::Queue<struct KAFKA_MESSAGE> message_queue;
            };
        } // namespace Kafka
    }     // namespace Util
} // namespace EDR

#endif