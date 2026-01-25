#pragma once
#ifdef SHARED
#include "export.h"
#else
#define DOG_CRYPTION_API
#endif

#include <thread>
#include <future>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <iostream>

#include "asyncion/asyncion.h"


namespace dog_torch::asyncion::thread
{
	class DOG_CRYPTION_API PauseableDetail
	{
	public:
		State state;
		double progress;
		uint64_t cost;
		PauseableDetail(State s, double p, uint64_t c);
	};

	class DOG_CRYPTION_API PauseableChannel
	{
	private:
		std::mutex mutex_;
		std::unique_ptr<std::condition_variable> condition_variable_;
		std::atomic<State> state_ = State::Ready;
		std::atomic<double> progress_ = 0;
		Clock<std::chrono::milliseconds> clock_;
	public:
		PauseableChannel();
		~PauseableChannel();
		PauseableChannel(const PauseableChannel& pc) = delete;
		PauseableChannel& operator=(const PauseableChannel&& pc) = delete;
		PauseableChannel(PauseableChannel&& pc)  noexcept;
		PauseableChannel& operator=(PauseableChannel&& pc) noexcept;

		void start();
		void pause();
		void resume();
		bool is_paused();
		void stop();
		bool is_stopped();
		void wait();
		bool should_pause();
		void add_progress(double value);
		void set_progress(double value);
		double get_progress();
		uint64_t get_ms_time() const;
		State get_state();

		PauseableDetail to_detail();
	};

	template<typename Func, typename... Args>
	concept PauseFunc = requires(Func f, dog_torch::asyncion::thread::PauseableChannel& pc, Args&&... args)
	{
		f(pc, std::forward<Args>(args)...);
	};

}