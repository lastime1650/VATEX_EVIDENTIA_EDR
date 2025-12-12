#ifndef KAFKA_H
#define KAFKA_H

#include <librdkafka/rdkafka.h>
#include <string>
#include <thread>
#include <atomic> // [추가] 스레드 플래그 안전성 확보

#include "queue.hpp"

// Windows 환경 가정 (ULONG32)
// 필요시 #include <Windows.h> 혹은 typedef uint32_t ULONG32;

namespace EDR
{
    namespace Util
    {
        namespace Kafka
        {
            class Kafka
            {
            public:
                Kafka(std::string broker_ip, ULONG32 broker_port, std::string topic)
                    : BrokerIp(std::move(broker_ip))
                    , BrokerPort(broker_port)
                    , Topic(std::move(topic))
                    , rk(nullptr)
                    , rkt(nullptr)
                    , is_worked(false)
                {
                }

                ~Kafka();

                // 복사 방지 (리소스 중복 해제 방지)
                Kafka(const Kafka&) = delete;
                Kafka& operator=(const Kafka&) = delete;

                // 초기화 및 Producer 생성
                bool Initialize();

                // 메시지를 큐에 적재 (Thread-Safe)
                void InsertMessage(const std::string& jsonMessage);

            private:
                // 실제 전송을 담당하는 내부 워커 스레드 함수
                void WorkerThread();

            private:
                // 스레드 제어 플래그 (Atomic 보장)
                std::atomic<bool> is_worked;

                rd_kafka_t* rk;
                rd_kafka_topic_t* rkt;

                std::string Topic;
                std::string BrokerIp;
                ULONG32 BrokerPort;

                // Thread-safe Queue
                EDR::Util::Queue::Queue<std::string> MessageQueue;

                std::thread QueueThread;
            };
        }
    }
}

#endif // KAFKA_H