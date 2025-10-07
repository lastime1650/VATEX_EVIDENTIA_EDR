#ifndef QUEUE_H
#define QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>

namespace EDR
{
    namespace Util
    {
        namespace Queue
        {
            class IQueue {
            public:
                virtual void putRaw(const void* data) = 0;
                virtual void putPtr(std::unique_ptr<void, void(*)(void*)> data) = 0;
                virtual ~IQueue() = default;
            };


            template <typename T>
            class Queue : public IQueue {
            public:
                Queue() = default;
                ~Queue() = default;

                void putPtr(std::unique_ptr<void, void(*)(void*)> data) override {
                    // data는 void* → T*로 캐스팅
                    T* typedData = static_cast<T*>(data.get());

                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        queue.push(std::move(*typedData)); // move semantics
                    }

                    condition.notify_one();

                    // 소유권 해제
                    data.release();
                }

                // 큐에 아이템(포인터) 추가
                void putRaw(const void* data) override {
                    const T* typedData = static_cast<const T*>(data);
                    put(*typedData); // 혹은 move 가능
                }

                // 큐에 아이템 추가
                void put(const T& item) {
                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        queue.push(item);
                    }
                    condition.notify_one();
                }

                // move semantics 지원
                void put(T&& item) {
                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        queue.push(std::move(item));
                    }
                    condition.notify_one();
                }

                // 큐에서 아이템 가져오기 (블로킹)
                T get() {
                    std::unique_lock<std::mutex> lock(mutex);
                    condition.wait(lock, [this]{ return !queue.empty(); });
                    T item = std::move(queue.front());
                    queue.pop();
                    return item;
                }

                // 큐 비었는지 확인
                bool empty() const {
                    std::lock_guard<std::mutex> lock(mutex);
                    return queue.empty();
                }


                // 큐 크기
                size_t size() const {
                    std::lock_guard<std::mutex> lock(mutex);
                    return queue.size();
                }

            private:

                mutable std::mutex mutex;
                std::queue<T> queue;
                std::condition_variable condition;
            };
        }
    }
}



#endif