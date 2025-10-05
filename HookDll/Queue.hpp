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
                    // data�� void* �� T*�� ĳ����
                    T* typedData = static_cast<T*>(data.get());

                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        queue.push(std::move(*typedData)); // move semantics
                    }

                    condition.notify_one();

                    // ������ ����
                    data.release();
                }

                // ť�� ������(������) �߰�
                void putRaw(const void* data) override {
                    const T* typedData = static_cast<const T*>(data);
                    put(*typedData); // Ȥ�� move ����
                }

                // ť�� ������ �߰�
                void put(const T& item) {
                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        queue.push(item);
                    }
                    condition.notify_one();
                }

                // move semantics ����
                void put(T&& item) {
                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        queue.push(std::move(item));
                    }
                    condition.notify_one();
                }

                // ť���� ������ �������� (���ŷ)
                T get() {
                    std::unique_lock<std::mutex> lock(mutex);
                    condition.wait(lock, [this] { return !queue.empty(); });
                    T item = std::move(queue.front());
                    queue.pop();
                    return item;
                }

                // ť ������� Ȯ��
                bool empty() const {
                    std::lock_guard<std::mutex> lock(mutex);
                    return queue.empty();
                }


                // ť ũ��
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