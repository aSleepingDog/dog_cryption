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

namespace dog_torch::asyncion::pool
{
	/**
	* 线程池
	*/
	class ThreadPool
	{
	private:
        std::mutex mutex_;
		std::atomic<State> status_;
		std::atomic<uint64_t> worker_count_;
		asyncion::container::VectorMove<std::thread> workers_;
		asyncion::container::DequeCopy<std::function<void()>> tasks_;
	public:
		ThreadPool(uint64_t count)
		{
			worker_count_.store(count);
			workers_.reserve(count);
		}
		~ThreadPool()
		{
			this->stop();
		}

		void start()
		{
			status_.store(State::Running);
			auto work = [this]()->void
				{
					while (this->status_.load() != State::Completely && this->status_.load() != State::Cancelled)
					{
						std::unique_lock lock(this->mutex_);
						if (this->tasks_.empty())
						{
							lock.unlock();
							std::this_thread::yield();
						}
						else
						{
							auto doing = this->tasks_.front();
							this->tasks_.pop_front();
							lock.unlock();
							try
							{
								doing();
							}
							catch (std::exception& e)
							{
								std::cout << e.what() << std::endl;
							}
							std::this_thread::yield();
						}
					}
				};
			for (uint64_t i = 0; i < worker_count_.load(); ++i)
			{
				workers_.emplace_back(std::move(std::thread(work)));
			}
		}
		void wait_complete()
		{
			while (status_.load() == State::Running)
			{
				if (tasks_.empty()) break;
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}
		}
		void pause()
		{
			status_.store(State::Paused);
		}
		void stop()
		{
			status_.store(State::Completely);
			auto waiting = [](std::vector<std::thread>& workers)-> void
				{
					for (auto& worker : workers)
					{
						worker.join();
					}
				};
			workers_.doing(waiting);
		}

		template<typename Func, typename... Args>
		auto add_task(Func&& func, Args&&... args) -> std::future<decltype(func(std::forward<Args>(args)...))>
		{
			using ResType = decltype(func(std::forward<Args>(args)...));
			using promRes = std::promise<ResType>;

			std::shared_ptr<promRes> prom = std::make_shared<promRes>();
			auto func_bind = std::bind(func, std::forward<Args>(args)...);
			std::function<void()> task;
			if constexpr (std::is_void_v<ResType>)
			{
				auto doing = [func_bind, prom]()->void
					{
						try
						{
							func_bind();
							prom->set_value();
						}
						catch (std::exception& e)
						{
							prom->set_exception(std::make_exception_ptr(e));
						}
					};
				task = std::move(doing);
			}
			else
			{
				auto doing = [func_bind, prom]()->void
					{
						try
						{
							prom->set_value(func_bind());
						}
						catch (std::exception& e)
						{
							prom->set_exception(std::make_exception_ptr(e));
						}
					};
				task = std::move(doing);
			}
			this->tasks_.emplace_back(std::move(task));
			return std::move(prom->get_future());
		}

	};

}