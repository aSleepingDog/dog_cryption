#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <future>
#include <iostream>
#include <print>
#include <unordered_set>
#include <coroutine>
#include <cmath>

namespace dog_torch::asyncion::coroutine
{
	class AwaitableBase
	{
	private:
		bool is_pause_;
	public:
		AwaitableBase(bool is_pause) : is_pause_(is_pause) {}
		bool is_pause() const { return is_pause_; }
		bool await_ready() noexcept
		{
			return is_pause_;
		}
		void await_suspend(std::coroutine_handle<> handle) noexcept {}
		void await_resume() noexcept {}
	};

	template<typename Coroutine>
	class PromiseType
	{
	private:
		bool is_pause_;
		double progress_;
	public:
		Coroutine get_return_object()
		{
			return Coroutine{ std::coroutine_handle<PromiseType>::from_promise(*this) };
		}
		AwaitableBase initial_suspend()
		{
			return AwaitableBase{ false };
		}
		double return_value() { return progress_; }
		AwaitableBase yield_value(double progress)
		{
			this->progress_ = progress;
			return AwaitableBase{ this->is_pause_ };
		}
		void unhandled_exception() {}
		AwaitableBase final_suspend() noexcept
		{
			return AwaitableBase{ true };
		}
	};

	class Coroutine
	{
	public:
		class promise_type
		{
		public:
			bool is_pause_ = false;
			double progress_ = 0;

			Coroutine get_return_object()
			{
				return Coroutine{ std::coroutine_handle<promise_type>::from_promise(*this) };
			}
			AwaitableBase initial_suspend()
			{
				return AwaitableBase{ false };
			}
			void return_void() {};
			AwaitableBase yield_value(double progress)
			{
				this->progress_ = progress;
				return AwaitableBase{ !this->is_pause_ };
			}
			void unhandled_exception() {}
			AwaitableBase final_suspend() noexcept
			{
				return AwaitableBase{ true };
			}
		};
	private:
		std::coroutine_handle<promise_type> handle_;
	public:
		Coroutine(std::coroutine_handle<promise_type> handle) : handle_(handle) {}
		bool done() const { return handle_.done(); }
		void start()
		{
			this->handle_.resume();
		}
		void pause()
		{
			this->handle_.promise().is_pause_ = true;
		}
		void resume()
		{
			this->handle_.promise().is_pause_ = false;
			this->handle_.resume();
		}
	};
}