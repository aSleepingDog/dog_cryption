#pragma once
#ifdef SHARED
#include "export.h"
#else
#define DOG_CRYPTION_API
#endif

#include <thread>
#include <future>
#include <chrono>
#include <iostream>

#include "asyncion/container/vector.h"
#include "asyncion/container/deque.h"


namespace dog_torch { namespace asyncion { namespace pool {

    class DOG_CRYPTION_API PollingPriorityTaskPool
    {
    private:
        class Work
        {
        private:
            std::future<void> future_status;
            std::thread work;
        public:
            Work(std::future<void> future_status, std::thread work)
                : future_status(std::move(future_status)), work(std::move(work)) {}
            ~Work() { if (work.joinable()) work.join(); }
            
            std::future<void>& get_future() { return future_status; }
            std::thread& get_thread() { return work; }

            Work(const Work&) = delete;
            Work& operator=(const Work&) = delete;
            Work(Work&& other)
            {
                this->future_status = std::move(other.future_status);
                this->work = std::move(other.work);
            }
            Work& operator=(Work&& other)
            {
                this->future_status = std::move(other.future_status);
                this->work = std::move(other.work);
                return *this;
            }
        };
        class Task
        {
        public:
            uint64_t priority;
            std::function<void(std::promise<void>&&)> func;
            Task(uint64_t priority, std::function<void(std::promise<void>&&)> func)
                : priority(priority), func(std::move(func)) {
            }
            Task() = default;
        };
    private:
        std::mutex mutex_;
        std::atomic<bool> status_;//true:running false:stop
        std::atomic<uint64_t> max_size_;//thread pool size
        dog_torch::asyncion::container::DequeMove<Work> threads_;
        dog_torch::asyncion::container::DequeCopy<Task> tasks_;
        std::thread manager_;
    public:
        static void manage(PollingPriorityTaskPool& pool)
        {
            uint64_t task_num;
            uint64_t thread_num;
            auto earse = [](std::deque<Work>& vec)
                {
                    static auto time = std::chrono::seconds(1);
                    for (auto it = vec.begin(); it != vec.end(); ++it)
                    {
                        if (it->get_future().wait_for(time) == std::future_status::ready)
                        {
                            if (it->get_thread().joinable())
                            {
                                it->get_thread().join();
                            }
                            it = vec.erase(it);
                            if (it == vec.end())
                            {
                                break;
                            }
                        }
                    }
                };
            try
            {
                while (pool.status_.load())
                {
                    std::lock_guard<std::mutex> lock(pool.mutex_);

                    task_num = pool.tasks_.size();
                    thread_num = pool.threads_.size();
                    if (task_num > 0 && thread_num < pool.max_size_.load())
                    {
                        //添加任务
                        std::function<void(std::promise<void>&&)> task = pool.tasks_.front().func;
                        pool.tasks_.pop_front();
                        std::promise<void> promise;
                        std::future<void> future = promise.get_future();
                        std::thread thread(task, std::move(promise));
                        Work one = { std::move(future), std::move(thread) };
                        pool.threads_.push_back(std::move(one));
                    }
                    else
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        //移除任务
                        pool.threads_.doing(earse);
                    }
                }
            }
            catch (std::exception& e)
            {
                std::cout << e.what() << std::endl;
            }
            catch (...)
            {

            }
        }
        PollingPriorityTaskPool(uint64_t max_size)
        {
            this->max_size_ = max_size;
            this->status_.store(false);
        }
        ~PollingPriorityTaskPool()
        {
            this->force_stop();
        }

        PollingPriorityTaskPool(const PollingPriorityTaskPool&) = delete;
        PollingPriorityTaskPool& operator=(const PollingPriorityTaskPool&) = delete;
        PollingPriorityTaskPool(PollingPriorityTaskPool&& other) noexcept
        {
            this->status_ = other.status_.load();
            this->max_size_ = other.max_size_.load();
            this->threads_ = std::move(other.threads_);
            this->tasks_ = std::move(other.tasks_);
            this->manager_ = std::move(other.manager_);
        }
        PollingPriorityTaskPool& operator=(PollingPriorityTaskPool&& other) noexcept
        {
            this->status_ = other.status_.load();
            this->max_size_ = other.max_size_.load();
            this->threads_ = std::move(other.threads_);
            this->tasks_ = std::move(other.tasks_);
            this->manager_ = std::move(other.manager_);
            return *this;
        }

        void start()
        {
            if (status_.load()) return;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                this->status_.store(true);
            }
            this->manager_ = std::thread(PollingPriorityTaskPool::manage, std::ref(*this));
        }
        void wait_complete()
        {
            while (true)
            {
                if (threads_.empty() && tasks_.empty())
                {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        void force_stop()
        {
            tasks_.clear();
            status_.store(false);
            manager_.join();
        }

        template<typename Func, typename... Args>
        auto add_task(uint64_t priority, Func&& func, Args&&... args) -> std::future<decltype(func(std::forward<Args>(args)...))>
        {
            using ResType = decltype(func(std::forward<Args>(args)...));
            using promRes = std::promise<ResType>;
            using promStatus = std::promise<void>;

            Task task_func;
            task_func.priority = priority;
            std::shared_ptr<promRes> promise_res_ptr;
            if constexpr (std::is_void_v<ResType>)
            {
                promise_res_ptr = std::make_shared<promRes>();
                auto func_bind = std::bind(func, args...);
                auto task = [func_bind, promise_res_ptr](promStatus&& promise_status) -> void
                    {
                        try
                        {
                            func_bind();
                            promise_res_ptr->set_value();
                            promise_status.set_value();
                        }
                        catch (std::exception& e)
                        {
                            promise_status.set_exception(std::make_exception_ptr(e));
                        }
                        catch (...)
                        {
                            promise_status.set_exception(std::make_exception_ptr(std::runtime_error("unknow error")));
                        }

                    };
                task_func.func = std::move(task);
            }
            else
            {
                promise_res_ptr = std::make_shared<promRes>();
                auto func_bind = std::bind(func, args...);
                auto task = [func_bind, promise_res_ptr](promStatus&& promise_status) -> void
                    {
                        try
                        {
                            auto res = func_bind();
                            promise_res_ptr->set_value(res);
                            promise_status.set_value();
                        }
                        catch (std::exception& e)
                        {
                            promise_status.set_exception(std::make_exception_ptr(e));
                        }
                        catch (...)
                        {
                            promise_status.set_exception(std::make_exception_ptr(std::runtime_error("unknow error")));
                        }

                    };
                task_func.func = std::move(task);
            }
            std::lock_guard<std::mutex> lock(mutex_);
            auto insert = [&task_func](std::deque<Task>& tasks)->void
                {
                    if (tasks.empty())
                    {
                        tasks.emplace_back(std::move(task_func));
                    }
                    else
                    {
                        for (auto it = tasks.begin(); it != tasks.end(); ++it)
                        {
                            if (it->priority > task_func.priority)
                            {
                                tasks.insert(it, std::move(task_func));
                                break;
                            }
                        }
                    }
                };
            tasks_.doing(insert);
            return std::move(promise_res_ptr->get_future());
        }
    };

}}}