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

                // Kafka ���ε༭ ����
                rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
                if (!rk) {
                    std::cerr << "Failed to create Kafka producer: " << errstr << std::endl;
                    return false;
                }

                // ���Ŀ �߰�
                std::ostringstream oss;
                oss << BrokerIp << ":" << BrokerPort; // "localhost:1234"
                std::string broker_info = oss.str();
                std::cout << broker_info << std::endl;
                if (rd_kafka_brokers_add(rk, broker_info.c_str()) == 0) {
                    std::cerr << "No valid brokers specified" << std::endl;
                    rd_kafka_destroy(rk);
                    return false;
                }

                // Topic �ڵ� ( ������ ������ �ڵ� ���� �����ϵ��� )
                rkt = rd_kafka_topic_new(rk, Topic.c_str(), nullptr);
                if (!rkt) {
                    std::cerr << "Failed to create topic object" << std::endl;
                    rd_kafka_destroy(rk);
                    return false;
                }

                // JSON(str) Message�� ���������� ���� ť ���� ( Private -> MessageQueue )

                // Message ť�� ���������� ������ ������ ����
                is_worked = true; // �ʱ�ȭ ����
                QueueThread = std::thread(
                    [this]()
                    {
                        std::cout << "Kafka ť ������ ����" << std::endl;

                        while (this->is_worked)
                        {
                            std::string json_message = this->MessageQueue.get();
                            if (!json_message.size())
                                continue;

                            //std::cout << "[Kafka Message ����] ->" << json_message << std::endl;

                            // ����
                            if (!this->rkt)
                                return;

                            rd_kafka_produce(
                                this->rkt,
                                RD_KAFKA_PARTITION_UA,  // ��Ƽ�� �ڵ� �Ҵ�
                                RD_KAFKA_MSG_F_COPY,    // ������ ����
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

                // thread ���� ���
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
                // ���� '\'�� '\\'�� ��ȯ
                std::string sanitizedMessage;
                sanitizedMessage.reserve(jsonMessage.size()); // ���� ����ȭ

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