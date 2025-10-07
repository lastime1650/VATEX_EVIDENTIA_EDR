#ifndef KAFKA_H
#define KAKFA_H

#include <librdkafka/rdkafka.h>
#include <string>
#include <linux/types.h>
#include "../queue/Queue.h"
#include <thread>
#include <iostream>
#include <sstream>

namespace EDR
{
    namespace Util
    {
        namespace Kafka
        {
            class Kafka
            {
                public:
                Kafka(std::string broker_ip, __u32 broker_port, std::string topic) : BrokerIp(broker_ip), BrokerPort(broker_port), Topic(topic){}
                ~Kafka()
                {
                    std::cout << "~Kafka called" << std::endl;
                    // thread 종료 대기
                    if(is_worked)
                    {
                        is_worked = false;
                        if(QueueThread.joinable())
                        {
                            QueueThread.join();
                        }
                    }

                    if (rkt)
                    {
                        rd_kafka_topic_destroy(rkt);
                    }

                    if(rk)
                    {
                        rd_kafka_destroy(rk);
                    }

                }
                
                bool Initialize()
                {
                    std::cout << "[Kafka]{Notice} Initialize called" << std::endl;
                    rd_kafka_conf_t* conf = rd_kafka_conf_new();

                    char errstr[512];

                    // Kafka 프로듀서 생성
                    rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
                    if (!rk) {
                        std::cerr << "Failed to create Kafka producer: " << errstr << std::endl;
                        return false;
                    }
                    std::cout << "[Kafka]{Notice} rd_kafka_new success" << std::endl;

                    // 브로커 추가
                    std::ostringstream oss;
                    oss << BrokerIp <<":"<< BrokerPort ; // "localhost:1234"
                    std::string broker_info = oss.str();
                    std::cout << broker_info << std::endl;
                    if (rd_kafka_brokers_add(rk, broker_info.c_str()) == 0) {
                        std::cerr << "No valid brokers specified" << std::endl;
                        rd_kafka_destroy(rk);
                        return false;
                    }
                    std::cout << "[Kafka]{Notice} rd_kafka_brokers_add success" << std::endl;

                    // Topic 핸들 ( 토픽이 없으면 자동 생성 가능하도록 )
                    rkt = rd_kafka_topic_new(rk, Topic.c_str(), nullptr);
                    if (!rkt) {
                        std::cerr << "Failed to create topic object" << std::endl;
                        rd_kafka_destroy(rk);
                        return false;
                    }
                    std::cout << "[Kafka]{Notice} rd_kafka_topic_new success" << std::endl;
                    
                    // JSON(str) Message를 지속적으로 받을 큐 생성 ( Private -> MessageQueue )

                    // Message 큐를 지속적으로 수신할 스레드 생성
                    is_worked = true; // 초기화 성공
                    QueueThread = std::thread(
                        [this]()
                        {
                            std::cout << "[Kafka]{Notice} QueueThread starting" << std::endl;
                            while(this->is_worked)
                            {
                                std::string json_message = this->MessageQueue.get();
                                if(!json_message.size())
                                    continue;

                                //std::cout << "[Kafka Message 받음] ->" << json_message << std::endl;

                                // 전송
                                if(! this->rkt)
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
                            std::cout << "[Kafka]{Notice} QueueThread stop" << std::endl;
                        }
                    );

                    return true;
                }

                
                
                void InsertMessage(const json& jsonMessage)
                {
                    try
                    {
                        MessageQueue.put(jsonMessage.dump());
                    }
                    catch(const std::exception& e)
                    {
                        std::cerr << e.what() << '\n';
                        throw std::runtime_error(e.what());
                    }
                    
                    
                }

                private:

                    bool is_worked = false;

                    rd_kafka_t* rk;
                    rd_kafka_topic_t* rkt; // with Topic

                    std::string Topic;
                    std::string BrokerIp;
                    __u32 BrokerPort;

                    EDR::Util::Queue::Queue<std::string> MessageQueue;
                    std::thread QueueThread;
            };
        }
    }
}

#endif