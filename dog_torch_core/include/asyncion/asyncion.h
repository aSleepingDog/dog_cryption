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

#include "math/number.h"

namespace dog_torch::asyncion
{
	enum class State : uint8_t
	{
		Ready = 0,
		Running = 1,
		Paused = 2,
		Waiting = 3,
		Completely = 4,
		Cancelled = 5
	};

	DOG_CRYPTION_API std::string State_to_str(State code);

	const std::vector<std::tuple<std::string, std::string, uint64_t, uint64_t>> transform_table_ =
	{ {"ns",".",3, 1000},{"us",".",3, 1000},{"ms",".",3, 1000},{"s",".",2, 60},{"min",":",2, 60},{"h",":",2, 24},{"d"," ",2, 7},{"w"," ",1,1} };

	template<typename Dur>
	concept is_std_Duration =
		std::is_same_v<Dur, std::chrono::nanoseconds> ||
		std::is_same_v<Dur, std::chrono::microseconds> ||
		std::is_same_v<Dur, std::chrono::milliseconds> ||
		std::is_same_v<Dur, std::chrono::seconds> ||
		std::is_same_v<Dur, std::chrono::minutes> ||
		std::is_same_v<Dur, std::chrono::hours> ||
		std::is_same_v<Dur, std::chrono::days> ||
		std::is_same_v<Dur, std::chrono::weeks>;

	template<is_std_Duration Dur>
	class DOG_CRYPTION_API Clock
	{
	private:
		State state_ = State::Ready;
		std::chrono::steady_clock::time_point start_time_;
		std::chrono::steady_clock::time_point end_time_;
		uint64_t total_ = 0;
	public:
		Clock()
		{
			start_time_ = std::chrono::steady_clock::now();
			end_time_ = std::chrono::steady_clock::now();
		}
		void start()
		{
			if (this->state_ == State::Ready)
			{
				start_time_ = std::chrono::steady_clock::now();
				this->state_ = State::Running;
			}
		};
		void reset()
		{
			this->state_ = State::Ready;
			this->total_ = 0;
		}
		void pause()
		{
			if (this->state_ == State::Running)
			{
				end_time_ = std::chrono::steady_clock::now();
				total_ += std::chrono::duration_cast<Dur>(end_time_ - start_time_).count();
				this->state_ = State::Paused;
			}
		}
		void resume()
		{
			if (this->state_ == State::Paused)
			{
				start_time_ = std::chrono::steady_clock::now();
				this->state_ = State::Running;
			}
		}
		void stop()
		{
			switch (this->state_)
			{
			case State::Running:
			case State::Paused:
			{
				this->state_ = State::Completely;
			}
			}
		}
		uint64_t get_cost() const
		{
			if (this->state_ == State::Running)
			{
				return total_ + std::chrono::duration_cast<Dur>(std::chrono::steady_clock::now() - start_time_).count();
			}
			return total_;
		}
		static std::string fmt_cost(uint64_t time)
		{
			uint64_t total = time;
			std::string result;
			uint64_t i = 0;
			if constexpr (std::is_same_v<Dur, std::chrono::nanoseconds>)
			{
				i = 0;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::microseconds>)
			{
				i = 1;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::milliseconds>)
			{
				i = 2;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::seconds>)
			{
				i = 3;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::minutes>)
			{
				i = 4;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::hours>)
			{
				i = 5;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::days>)
			{
				i = 6;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::weeks>)
			{
				i = 7;
			}
			for (;i < transform_table_.size();i++)
			{
				if (total == 0 && !result.empty())
				{
					break;
				}
				uint64_t mod = total % std::get<3>(transform_table_[i]);
				if (mod > 0 || result.empty())
				{
					result = std::format("{}{}", mod, std::get<0>(transform_table_[i])) + result;
				}
				total /= std::get<3>(transform_table_[i]);
			}
			return result;
		}
		static std::string iso_fmt_cost(uint64_t time)
		{
			uint64_t total = time;
			std::string result;
			uint64_t i = 0;
			if constexpr (std::is_same_v<Dur, std::chrono::nanoseconds>)
			{
				i = 0;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::microseconds>)
			{
				i = 1;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::milliseconds>)
			{
				i = 2;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::seconds>)
			{
				i = 3;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::minutes>)
			{
				i = 4;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::hours>)
			{
				i = 5;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::days>)
			{
				i = 6;
			}
			else if constexpr (std::is_same_v<Dur, std::chrono::weeks>)
			{
				i = 7;
			}
			for (;i < transform_table_.size();i++)
			{
				if (total == 0 && !result.empty())
				{
					break;
				}
				uint64_t mod = total % std::get<3>(transform_table_[i]);
				if (mod > 0 || result.empty())
				{
					//{:0>n}{}
					std::string fmt_str = "{:0>" + std::to_string(std::get<2>(transform_table_[i])) + "}{}";
					result = std::vformat(fmt_str, std::make_format_args(mod, (result.empty() ? "" : std::get<1>(transform_table_[i])))) + result;
				}
				total /= std::get<3>(transform_table_[i]);
			}
			return result;
		}

	};

#ifdef SHARED
	extern template class DOG_CRYPTION_API Clock<std::chrono::nanoseconds>;
	extern template class DOG_CRYPTION_API Clock<std::chrono::microseconds>;
	extern template class DOG_CRYPTION_API Clock<std::chrono::milliseconds>;
	extern template class DOG_CRYPTION_API Clock<std::chrono::seconds>;
	extern template class DOG_CRYPTION_API Clock<std::chrono::minutes>;
	extern template class DOG_CRYPTION_API Clock<std::chrono::hours>;
	extern template class DOG_CRYPTION_API Clock<std::chrono::days>;
	extern template class DOG_CRYPTION_API Clock<std::chrono::weeks>;
#endif // SHARED

}