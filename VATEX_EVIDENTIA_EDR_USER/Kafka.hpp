#ifndef KAFKA_H
#define KAKFA_H

#include <librdkafka/rdkafka.h>
#include <string>
#include <thread>

#include "queue.hpp"

namespace EDR
{
    namespace Util
    {
        namespace Kafka
        {

            class Kafka
            {
            public:
                Kafka(std::string broker_ip, ULONG32 broker_port, std::string topic) : BrokerIp(broker_ip), BrokerPort(broker_port), Topic(topic) {}
                ~Kafka();

                bool Initialize();

                void InsertMessage(std::string jsonMessage); // MEssage ¸¦ Å¥·Î Put()

            private:

                bool is_worked = false;

                rd_kafka_t* rk;
                rd_kafka_topic_t* rkt; // with Topic

                std::string Topic;
                std::string BrokerIp;
                ULONG32 BrokerPort;

                EDR::Util::Queue::Queue<std::string> MessageQueue;
                std::thread QueueThread;
            };
        }
    }
}

#endif