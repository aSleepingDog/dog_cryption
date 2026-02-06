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
#include "asyncion/thread/thread.h"

namespace dog_torch::asyncion::pool
{
	/**
	* 可控制的线程池
	*/
	class PausedThreadPool
	{
	private:
		class Worker
		{
		public:
			dog_torch::asyncion::thread::PauseableChannel pchannel;
			std::thread thread;
			uint64_t task_id = 0;

			Worker() = default;

			Worker(const Worker&) = delete;

			Worker(Worker&& other) noexcept
			{
				this->pchannel = std::move(other.pchannel);
				this->thread = std::move(other.thread);
				this->task_id = other.task_id;
			};
			Worker& operator=(Worker&& other) noexcept
			{
				this->pchannel = std::move(other.pchannel);
				this->thread = std::move(other.thread);
				this->task_id = other.task_id;
				return *this;
			}
		};
		class Task
		{
		public:
			uint64_t id;
			std::function<void(dog_torch::asyncion::thread::PauseableChannel&)> func;
			Task(std::function<void(dog_torch::asyncion::thread::PauseableChannel&)>&& pfunc, uint64_t pid)
				: func(std::move(pfunc)), id(pid)
			{

			}
		};

        std::mutex mutex_;
		std::atomic<State> state_ = State::Ready;
		std::atomic<uint64_t> task_next_id_ = 1;
		std::atomic<uint64_t> worker_count_;
		asyncion::container::VectorMove<Worker> workers_;
		asyncion::container::DequeCopy<Task> tasks_;
	public:
		PausedThreadPool(uint64_t count)
		{
			worker_count_.store(count);
			workers_.reserve(count);
		}
		~PausedThreadPool()
		{
			this->stop_all();
		}

		void start()
		{
			using dog_torch::asyncion::thread::PauseableChannel;
			state_.store(State::Running);
			auto work = [this](Worker& self_worker)->void
				{
					while (this->state_.load() == State::Running)
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
								self_worker.task_id = doing.id;
								doing.func(self_worker.pchannel);
								self_worker.pchannel.complete();
							}
							catch (std::exception& e)
							{
								std::cout << e.what() << std::endl;
								self_worker.pchannel.cancel();
							}
							std::this_thread::yield();
						}
					}
				};
			workers_.doing([work, n = this->worker_count_.load()](std::vector<Worker>& vec)->void
				{
					vec.resize(n);
					for (auto& worker : vec)
					{
						worker.thread = std::thread(work, std::ref(worker));
					}
				}
			);
		}
		void wait_complete()
		{
			while (true)
			{
				if (tasks_.empty()) break;
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}
		}
		void pause_all()
		{
			state_.store(State::Paused);
			workers_.doing([](std::vector<Worker>& workers)->void
				{
					for (auto& worker : workers)
					{
						worker.pchannel.pause();
					}
				});
		}
		void stop_all()
		{
			state_.store(State::Completely);
			auto waiting = [](std::vector<Worker>& workers)-> void
				{
					for (auto& worker : workers)
					{
						worker.pchannel.cancel();
						worker.thread.join();
					}
				};
			workers_.doing(waiting);
		}

		std::vector<std::pair<uint64_t, dog_torch::asyncion::thread::PauseableDetail>> get_tasks_detail()
		{
			std::vector<std::pair<uint64_t, dog_torch::asyncion::thread::PauseableDetail>> details;
			auto get_detail = [&details](std::vector<Worker>& workers)-> void
				{
					for (auto& worker : workers)
					{
						if (worker.task_id != 0)
						{
							std::pair<uint64_t, dog_torch::asyncion::thread::PauseableDetail> item(
								worker.task_id, worker.pchannel.to_detail()
							);
							details.emplace_back(item);
							if (worker.pchannel.is_stopped())
							{
								worker.task_id = 0;
							}
						}
					}
				};
			workers_.doing(get_detail);
			return details;
		}

		bool pause(uint64_t task_id)
		{
			bool result = false;
			workers_.doing([&result, &task_id](std::vector<Worker>& workers)->void
				{
					for (auto& worker : workers)
					{
						if (worker.task_id == task_id)
						{
							worker.pchannel.pause();
							result = true;
							break;
						}
					}
				});
			return result;
		}
		bool resume(uint64_t task_id)
		{
			bool result = false;
			workers_.doing([&result, &task_id](std::vector<Worker>& workers)->void
				{
					for (auto& worker : workers)
					{
						if (worker.task_id == task_id)
						{
							worker.pchannel.resume();
							result = true;
							break;
						}
					}
				});
			return result;
		}
		bool stop(uint64_t task_id)
		{
			bool result = false;
			workers_.doing([&result, &task_id](std::vector<Worker>& workers)->void
				{
					for (auto& worker : workers)
					{
						if (worker.task_id == task_id)
						{
							worker.pchannel.cancel();
							result = true;
							break;
						}
					}
				});
			return result;
		}

		template<typename Func, typename... Args>
			requires dog_torch::asyncion::thread::PauseFunc<Func, Args...>
		auto add_task(Func&& func, Args&&... args) -> std::pair<uint64_t, std::future<decltype(func(std::declval<dog_torch::asyncion::thread::PauseableChannel&>(), std::forward<Args>(args)...))>>
		{
			using dog_torch::asyncion::thread::PauseableChannel;
			using ResType = decltype(func(std::declval<dog_torch::asyncion::thread::PauseableChannel&>(), std::forward<Args>(args)...));
			using promRes = std::promise<ResType>;

			std::shared_ptr<promRes> prom = std::make_shared<promRes>();
			auto func_bind = std::bind(func, std::placeholders::_1, std::forward<Args>(args)...);
			std::function<void(PauseableChannel&)> task;
			if constexpr (std::is_void_v<ResType>)
			{
				auto doing = [func_bind, prom](PauseableChannel& pc)->void
					{
						try
						{
							func_bind(pc);
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
				auto doing = [func_bind, prom](PauseableChannel& pc)->void
					{
						try
						{
							prom->set_value(func_bind(pc));
						}
						catch (std::exception& e)
						{
							prom->set_exception(std::make_exception_ptr(e));
						}
					};
				task = std::move(doing);
			}
			std::lock_guard lock(this->mutex_);
			uint64_t task_id = this->task_next_id_;
			this->tasks_.emplace_back({ std::move(task),  task_id });
			this->task_next_id_++;
			return std::pair{ task_id, std::move(prom->get_future()) };
		}

	};

}