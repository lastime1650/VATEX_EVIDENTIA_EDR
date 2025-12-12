#include "Kafka.hpp"
#include <iostream>
#include <sstream>
// #include <chrono> // 필요 시 사용

namespace EDR
{
    namespace Util
    {
        namespace Kafka
        {
            // [설정] EDR 로그 특성상 데이터가 순간적으로 폭증할 수 있음
            // 시스템 메모리 보호를 위해 Kafka 내부 큐 크기 제한 설정이 중요
            bool Kafka::Initialize()
            {
                rd_kafka_conf_t* conf = rd_kafka_conf_new();
                char errstr[512];

                // 1. 네트워크 타임아웃 설정 (빠른 실패 감지)
                rd_kafka_conf_set(conf, "message.timeout.ms", "5000", errstr, sizeof(errstr));
                rd_kafka_conf_set(conf, "socket.timeout.ms", "3000", errstr, sizeof(errstr));

                // 2. 버퍼링 및 배치 설정 (실시간성 vs 처리량 균형)
                // linger.ms: 0이면 즉시 전송(실시간), 5ms면 약간 모아서 전송(CPU 절약). 
                // EDR은 0~5ms 권장. 
                rd_kafka_conf_set(conf, "linger.ms", "0", errstr, sizeof(errstr));

                rd_kafka_conf_set(conf, "message.max.bytes", "10485760", errstr, sizeof(errstr)); // 10MB
                rd_kafka_conf_set(conf, "receive.message.max.bytes", "10485760", errstr, sizeof(errstr));

                // 3. 메모리 보호 설정 (중요)
                // 큐가 가득 차면 produce는 에러를 뱉고, 우리는 이를 제어해야 함
                rd_kafka_conf_set(conf, "queue.buffering.max.messages", "100000", errstr, sizeof(errstr));
                rd_kafka_conf_set(conf, "queue.buffering.max.kbytes", "102400", errstr, sizeof(errstr)); // 100MB

                // 4. 압축 (네트워크 대역폭 절약)
                //rd_kafka_conf_set(conf, "compression.type", "lz4", errstr, sizeof(errstr));
                rd_kafka_conf_set(conf, "compression.type", "none", errstr, sizeof(errstr));

                // Kafka 프로듀서 생성
                rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
                if (!rk) {
                    std::cerr << "[EDR-Kafka] Failed to create producer: " << errstr << std::endl;
                    return false;
                }

                // 브로커 추가
                std::ostringstream oss;
                oss << BrokerIp << ":" << BrokerPort;
                if (rd_kafka_brokers_add(rk, oss.str().c_str()) == 0) {
                    std::cerr << "[EDR-Kafka] No valid brokers specified" << std::endl;
                    rd_kafka_destroy(rk);
                    return false;
                }

                // 토픽 핸들 생성
                rkt = rd_kafka_topic_new(rk, Topic.c_str(), nullptr);
                if (!rkt) {
                    std::cerr << "[EDR-Kafka] Failed to create topic object" << std::endl;
                    rd_kafka_destroy(rk);
                    return false;
                }

                // 스레드 시작
                is_worked = true;
                QueueThread = std::thread(&Kafka::WorkerThread, this);

                return true;
            }

            // 실제 전송을 담당하는 워커 스레드 로직 분리
            void Kafka::WorkerThread()
            {
                std::cout << "[EDR-Kafka] Worker Thread Started." << std::endl;

                while (this->is_worked)
                {
                    // 1. 큐에서 메시지 가져오기
                    // (가정: MessageQueue.get()은 데이터가 없으면 빈 문자열을 즉시 리턴하거나, 
                    //  짧은 시간 블로킹 후 리턴한다고 가정합니다. 
                    //  만약 완전 블로킹 함수라면 별도의 타임아웃 처리가 필요할 수 있습니다.)
                    std::string json_message = this->MessageQueue.get();

                    // 2. 데이터가 없는 경우 (Idle)
                    if (json_message.empty())
                    {
                        // CPU 과점유 방지 및 Kafka 콜백(Delivery Report) 처리
                        // 데이터가 없을 때는 느긋하게 poll을 수행
                        if (this->rk) rd_kafka_poll(this->rk, 100);
                        continue;
                    }

                    // 3. 데이터 전송 (Retry 로직 포함)
                    bool message_sent = false;
                    while (!message_sent && this->is_worked)
                    {
                        int err = rd_kafka_produce(
                            this->rkt,
                            RD_KAFKA_PARTITION_UA,
                            RD_KAFKA_MSG_F_COPY,
                            (void*)json_message.c_str(),
                            json_message.size(),
                            nullptr, 0, nullptr
                        );

                        if (err == 0)
                        {
                            // 성공: 즉시 non-blocking poll로 콜백 처리 후 다음 메시지로 이동
                            // poll(0)은 매우 빠름.
                            rd_kafka_poll(this->rk, 0);
                            message_sent = true;
                        }
                        else
                        {
                            // 실패 처리
                            rd_kafka_resp_err_t last_err = rd_kafka_last_error();

                            // 큐가 가득 찼다면 (네트워크 지연 등)
                            if (last_err == RD_KAFKA_RESP_ERR__QUEUE_FULL)
                            {
                                // 내부 버퍼를 비우기 위해 blocking poll 호출 (Backpressure)
                                // 50ms 정도 대기하며 이벤트를 처리함
                                rd_kafka_poll(this->rk, 50);
                                // 루프를 돌며 재시도 함
                            }
                            else if (last_err == RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE)
                            {
                                std::cerr << "[EDR-Kafka] Drop message: Too large" << std::endl;
                                message_sent = true; // 재시도 하지 않고 버림
                            }
                            else
                            {
                                // 기타 에러: 일단 로그 찍고 재시도 혹은 스킵
                                // 알 수 없는 에러면 스킵하는 게 안전함 (무한 루프 방지)
                                std::cerr << "[EDR-Kafka] Produce failed: " << rd_kafka_err2str(last_err) << std::endl;
                                message_sent = true; // 버림
                            }
                        }
                    }
                }
            }

            void Kafka::InsertMessage(const std::string& jsonMessage)
            {
                // [안전장치]
                // 만약 MessageQueue 자체가 제한이 없는 큐라면, 
                // EDR 로그 폭주시 메모리가 터질 수 있습니다.
                // 큐 구현체 내부에 Max Size 체크가 있기를 권장합니다.
                if (!is_worked) return;
                MessageQueue.put(jsonMessage);
            }

            // 소멸자는 OS 종료 시에만 불리므로 로직 최소화
            // (하지만 만약을 대비해 최소한의 정리는 유지)
            Kafka::~Kafka()
            {
                is_worked = false;

                // 스레드가 종료되길 기다리지 않고 detach 할 수도 있지만,
                // 안전하게는 join을 시도하는 것이 좋습니다.
                if (QueueThread.joinable())
                {
                    // 큐가 블로킹 상태라면 여기서 멈출 수 있으나, 
                    // OS 강제 종료 상황이면 상관 없음.
                    // QueueThread.join(); 
                    QueueThread.detach();
                }

                if (rk)
                {
                    // 남은 메시지 배출 시도 (최대 1초만)
                    rd_kafka_flush(rk, 1000);
                    rd_kafka_topic_destroy(rkt);
                    rd_kafka_destroy(rk);
                }
            }
        }
    }
}