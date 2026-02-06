#pragma once
#ifdef SHARED
	#include "export.h"
#else
	#define DOG_CRYPTION_API
#endif

#include <deque>
#include <mutex>
#include <shared_mutex>
#include <functional>

namespace dog_torch::asyncion::container 
{
	/**
	* 可拷贝线程安全的std::deque封装
	*/
	template <typename T, typename Alloc = std::allocator<T>>
	class DequeCopy
	{
	private:
		using selfDqu = std::deque<T, Alloc>;
		using it = std::deque<T, Alloc>::iterator;
		using doSingleFunc = std::function<void(it)>;
		using doContainerFunc = std::function<void(selfDqu&)>;
		using doLoopFunc = std::function<void(selfDqu&, it)>;

		std::shared_mutex mutex_;
		std::deque<T, Alloc> deque_;

	public:
		DequeCopy() = default;
		~DequeCopy() = default;

		DequeCopy(const DequeCopy& other)
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			deque_ = other.deque_;
		}
		DequeCopy& operator=(const DequeCopy& other)
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			deque_ = other.deque_;
			return *this;
		}
		DequeCopy(DequeCopy&& other) noexcept
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			deque_ = std::move(other.deque_);
		}
		DequeCopy& operator=(DequeCopy&& other) noexcept
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			deque_ = std::move(other.deque_);
			return *this;
		}

		T at(size_t index)
		{
			std::shared_lock lock(mutex_);
			return deque_.at(index);
		}
		T operator[](size_t index)
		{
			std::shared_lock lock(mutex_);
			return deque_[index];
		}
		T front()
		{
			std::shared_lock lock(mutex_);
			return deque_.front();
		}
		T back()
		{
			std::shared_lock lock(mutex_);
			return deque_.back();
		}

		selfDqu get_all()
		{
			std::shared_lock lock(mutex_);
			return deque_;
		}
		void set_all(const selfDqu& other)
		{
			std::unique_lock lock(mutex_);
			deque_ = other;
		}
		void set_all(selfDqu&& other)
		{
			std::unique_lock lock(mutex_);
			deque_ = std::move(other);
		}

		bool empty()
		{
			std::shared_lock lock(mutex_);
			return deque_.empty();
		}
		size_t size()
		{
			std::shared_lock lock(mutex_);
			return deque_.size();
		}
		size_t max_size()
		{
			std::shared_lock lock(mutex_);
			return deque_.max_size();
		}
		void shrink_to_fit()
		{
			std::unique_lock lock(mutex_);
			return deque_.shrink_to_fit();
		}
		void clear()
		{
			std::unique_lock lock(mutex_);
			return deque_.clear();
		}
		void insert(size_t pos, const T& value)
		{
			std::unique_lock lock(mutex_);
			return deque_.insert(deque_.begin() + pos, std::move(value));
		}
		void emplace(size_t pos, const T& value)
		{
			std::unique_lock lock(mutex_);
			return deque_.emplace(deque_.begin() + pos, std::move(value));
		}
		void erase(size_t pos)
		{
			std::unique_lock lock(mutex_);
			return deque_.erase(deque_.begin() + pos);
		}
		void push_back(const T& value)
		{
			std::unique_lock lock(mutex_);
			deque_.push_back(value);
		}
		void emplace_back(const T& value)
		{
			std::unique_lock lock(mutex_);
			deque_.emplace_back(value);
		}
		void pop_back()
		{
			std::unique_lock lock(mutex_);
			deque_.pop_back();
		}
		void push_front(const T& value)
		{
			std::unique_lock lock(mutex_);
			deque_.push_front(value);
		}
		void emplace_front(const T& value)
		{
			std::unique_lock lock(mutex_);
			deque_.emplace_front(value);
		}
		void pop_front()
		{
			std::unique_lock lock(mutex_);
			deque_.pop_front();
		}
		void doing(size_t pos, doSingleFunc func)
		{
			std::unique_lock lock(mutex_);
			func(deque_.begin() + pos);
		}
		void doing(doContainerFunc func)
		{
			std::unique_lock lock(mutex_);
			func(deque_);
		}
		void doing(doLoopFunc func)
		{
			std::unique_lock lock(mutex_);
			for (auto it = deque_.begin(); it != deque_.end(); ++it)
			{
				func(deque_, it);
			}
		}
	};

	/**
	* 仅可移动线程安全的std::deque封装
	*/
	template <std::movable T, typename Alloc = std::allocator<T>>
	class DequeMove
	{
	private:
		using selfDqu = std::deque<T, Alloc>;
		using it = std::deque<T, Alloc>::iterator;
		using doSingleFunc = std::function<void(it)>;
		using doContainerFunc = std::function<void(selfDqu&)>;
		using doLoopFunc = std::function<void(selfDqu&, it)>;

		std::shared_mutex mutex_;
		std::deque<T, Alloc> deque_;

	public:
		DequeMove() = default;

		DequeMove(const DequeMove& other) = delete;
		DequeMove& operator=(const DequeMove& other) = delete;
		DequeMove(DequeMove&& other) noexcept
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			deque_ = std::move(other.deque_);
		}
		DequeMove& operator=(DequeMove&& other) noexcept
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			deque_ = std::move(other.deque_);
			return *this;
		}

		selfDqu take_all()
		{
			std::unique_lock lock(mutex_);
			return std::move(deque_);
		}
		void move_all(selfDqu&& other)
		{
			std::unique_lock lock(mutex_);
			deque_ = std::move(other);
		}

		T take(size_t index)
		{
			std::unique_lock lock(mutex_);
			auto tmp = std::move(deque_[index]);
			deque_.erase(deque_.begin() + index);
			return tmp;
		}
		T take_front()
		{
			std::unique_lock lock(mutex_);
			auto tmp = std::move(deque_.front());
			deque_.erase(deque_.begin());
			return tmp;
		}
		T take_back()
		{
			std::unique_lock lock(mutex_);
			auto tmp = std::move(deque_.back());
			deque_.erase(deque_.end());
			return tmp;
		}

		bool empty()
		{
			std::shared_lock lock(mutex_);
			return deque_.empty();
		}
		size_t size()
		{
			std::shared_lock lock(mutex_);
			return deque_.size();
		}
		size_t max_size()
		{
			std::shared_lock lock(mutex_);
			return deque_.max_size();
		}
		void shrink_to_fit()
		{
			std::unique_lock lock(mutex_);
			return deque_.shrink_to_fit();
		}
		void clear()
		{
			std::unique_lock lock(mutex_);
			return deque_.clear();
		}
		void insert(size_t pos, T&& value)
		{
			std::unique_lock lock(mutex_);
			return deque_.insert(deque_.begin() + pos, std::move(value));
		}
		void emplace(size_t pos, T&& value)
		{
			std::unique_lock lock(mutex_);
			return deque_.emplace(deque_.begin() + pos, std::move(value));
		}
		void erase(size_t pos)
		{
			std::unique_lock lock(mutex_);
			return deque_.erase(deque_.begin() + pos);
		}
		void push_back(T&& value)
		{
			std::unique_lock lock(mutex_);
			deque_.push_back(std::move(value));
		}
		void emplace_back(T&& value)
		{
			std::unique_lock lock(mutex_);
			deque_.emplace_back(std::move(value));
		}
		void pop_back()
		{
			std::unique_lock lock(mutex_);
			deque_.pop_back();
		}
		void push_front(T&& value)
		{
			std::unique_lock lock(mutex_);
			deque_.push_front(std::move(value));
		}
		void emplace_front(T&& value)
		{
			std::unique_lock lock(mutex_);
			deque_.emplace_front(std::move(value));
		}
		void pop_front()
		{
			std::unique_lock lock(mutex_);
			deque_.pop_front();
		}
		void doing(size_t pos, doSingleFunc func)
		{
			std::unique_lock lock(mutex_);
			func(deque_.begin() + pos);
		}
		void doing(doContainerFunc func)
		{
			std::unique_lock lock(mutex_);
			func(deque_);
		}
		void doing(doLoopFunc func)
		{
			std::unique_lock lock(mutex_);
			for (auto it = deque_.begin(); it != deque_.end(); ++it)
			{
				func(deque_, it);
			}
		}
	};
}