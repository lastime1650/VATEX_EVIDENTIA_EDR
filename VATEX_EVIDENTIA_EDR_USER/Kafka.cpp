#include "Kafka.hpp"

#include <iostream>
#include <sstream>

namespace EDR
{
    namespace Util
    {
        namespace Kafka
        {

            bool Kafka::Initialize()
            {
                rd_kafka_conf_t* conf = rd_kafka_conf_new();

                char errstr[512];

                // Kafka 프로듀서 생성
                rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
                if (!rk) {
                    std::cerr << "Failed to create Kafka producer: " << errstr << std::endl;
                    return false;
                }

                // 브로커 추가
                std::ostringstream oss;
                oss << BrokerIp << ":" << BrokerPort; // "localhost:1234"
                std::string broker_info = oss.str();
                std::cout << broker_info << std::endl;
                if (rd_kafka_brokers_add(rk, broker_info.c_str()) == 0) {
                    std::cerr << "No valid brokers specified" << std::endl;
                    rd_kafka_destroy(rk);
                    return false;
                }

                // Topic 핸들 ( 토픽이 없으면 자동 생성 가능하도록 )
                rkt = rd_kafka_topic_new(rk, Topic.c_str(), nullptr);
                if (!rkt) {
                    std::cerr << "Failed to create topic object" << std::endl;
                    rd_kafka_destroy(rk);
                    return false;
                }

                // JSON(str) Message를 지속적으로 받을 큐 생성 ( Private -> MessageQueue )

                // Message 큐를 지속적으로 수신할 스레드 생성
                is_worked = true; // 초기화 성공
                QueueThread = std::thread(
                    [this]()
                    {
                        std::cout << "Kafka 큐 스레드 실행" << std::endl;

                        while (this->is_worked)
                        {
                            std::string json_message = this->MessageQueue.get();
                            if (!json_message.size())
                                continue;

                            //std::cout << "[Kafka Message 받음] ->" << json_message << std::endl;

                            // 전송
                            if (!this->rkt)
                                return;

                            rd_kafka_produce(
                                this->rkt,
                                RD_KAFKA_PARTITION_UA,  // 파티션 자동 할당
                                RD_KAFKA_MSG_F_COPY,    // 데이터 복사
                                (void*)json_message.c_str(),
                                json_message.size(),
                                nullptr,
                                0,
                                nullptr
                            );

                            rd_kafka_poll(this->rk, 0);
                        }
                    }
                );

                return true;
            }

            Kafka::~Kafka()
            {

                // thread 종료 대기
                if (is_worked)
                {
                    is_worked = false;
                    if (QueueThread.joinable())
                    {
                        QueueThread.join();
                    }
                }

                if (rkt)
                {
                    rd_kafka_topic_destroy(rkt);
                }

                if (rk)
                {
                    rd_kafka_destroy(rk);
                }

            }

            void Kafka::InsertMessage(std::string jsonMessage)
            {
                /*
                // 단일 '\'를 '\\'로 변환
                std::string sanitizedMessage;
                sanitizedMessage.reserve(jsonMessage.size()); // 성능 최적화

                for (char c : jsonMessage) {
                    if (c == '\\') {
                        sanitizedMessage += "\\\\";
                    }
                    else {
                        sanitizedMessage += c;
                    }
                }*/

                MessageQueue.put(jsonMessage);
            }
        }
    }
}