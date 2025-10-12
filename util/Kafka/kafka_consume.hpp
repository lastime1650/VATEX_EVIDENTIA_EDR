#ifndef KAFKA_CONSUME_HPP
#define KAFKA_CONSUME_HPP

#include "../Queue/queue.hpp"
#include <string>
#include <atomic>
#include <thread>
#include <chrono>
#include <iostream>
#include <cppkafka/cppkafka.h>

#include "../json.hpp"

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
                  const std::string& topic
                ) : config_(
                    {
                        { "metadata.broker.list", brokers },
                        { "group.id", group_id },
                        { "enable.auto.commit", true },
                        { "auto.offset.reset", "earliest" }   
                    }),
                    consumer_(config_),
                    topic_(topic)
                {
                    /*
                        패턴 문자열은 ^로 시작해야 정규식 기반 매칭으로 인식
                    */
                    consumer_.subscribe( {topic_} );
                }
                ~Kafka_Consumer()
                {
                    Stop();
                }



                bool Run()
                {
                    if(is_working_thread)
                        return false;
                    
                    is_working_thread = true;
                    loopreceivethread = std::thread(
                        [this]()
                        {
                            while (this->is_working_thread)
                            {
                                cppkafka::Message msg = consumer_.poll();
                                if(msg)
                                {

                                    if(msg.get_error())
                                    {
                                        if(msg.is_eof())
                                        {
                                            std::this_thread::sleep_for(
                                                std::chrono::seconds(5)
                                            );
                                            continue;
                                        }
                                    }


                                    std::string topic = msg.get_topic();
                                    std::string message = msg.get_payload();
                                    unsigned long long offset = msg.get_offset();
                                    
                                    //std::cout << "[MESSAGE]: " << message << std::endl;

                                    json tojson_message;
                                    try{
                                        tojson_message = json::parse(message);
                                    }
                                    catch (json::parse_error &e)
                                    {
                                        std::cout << message << std::endl;
                                        std::cout << "[Kafka] Json parse failed: " << e.what() << std::endl;
                                        continue;
                                    }

                                    struct KAFKA_MESSAGE MessageObject = {
                                        .topic_name = topic,
                                        .offset = offset,
                                        .message = tojson_message,
                                        .original_message = message
                                    };

                                    this->message_queue.put(MessageObject);

                                }
                                else
                                {
                                    
                                    std::this_thread::sleep_for(
                                        std::chrono::seconds(5)
                                    );
                                    continue;
                                }
                            }
                            
                        }
                    );


                    return true;
                }

                bool Stop()
                {
                    if(!is_working_thread)
                        return false;
                    
                    is_working_thread = false;

                    if(loopreceivethread.joinable())
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

                std::string Topic;
                std::string BrokerIp;
                unsigned int BrokerPort;


                EDR::Util::Queue::Queue<struct KAFKA_MESSAGE> message_queue;

            };
        }
    }
}

#endif