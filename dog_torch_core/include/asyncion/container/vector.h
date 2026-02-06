#pragma once
#ifdef SHARED
	#include "export.h"
#else
	#define DOG_CRYPTION_API
#endif

#include <vector>
#include <mutex>
#include <shared_mutex>
#include <functional>

namespace dog_torch::asyncion::container
{
	/**
	* 可拷贝的线程安全的std::vector封装
	*/
    template <typename T, typename Alloc = std::allocator<T>>
	class VectorCopy
	{
		using selfVec = std::vector<T, Alloc>;
		using it = std::vector<T, Alloc>::iterator;
		using doSingleFunc = std::function<void(it)>;
		using doContainerFunc = std::function<void(it, it)>;
		using doLoopFunc = std::function<void(selfVec&, it)>;
	private:
		mutable std::shared_mutex mutex_;
		selfVec vec_;
	public:
		VectorCopy() = default;
		~VectorCopy() = default;

		VectorCopy(const VectorCopy& other)
		{
			std::scoped_lock(mutex_, other.mutex_);
			vec_ = other.vec_;
		}
		VectorCopy& operator=(const VectorCopy& other)
		{
			std::scoped_lock(mutex_, other.mutex_);
			vec_ = other.vec_;
			return *this;
		}
		VectorCopy(VectorCopy&& other) noexcept
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			this->vec_ = std::move(other.vec_);
		}
		VectorCopy& operator=(VectorCopy&& other) noexcept
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			this->vec_ = std::move(other.vec_);
			return *this;
		}


		selfVec get_all() const
		{
			std::shared_lock lock(mutex_);
			return vec_;
		}
		void set_all(const selfVec& vec)
		{
			std::unique_lock lock(mutex_);
			this->vec_ = vec;
		}
		void set_all(selfVec&& vec)
		{
			std::unique_lock lock(mutex_);
			this->vec_ = std::move(vec);
		}
		T at(size_t index) const
		{
			std::shared_lock lock(mutex_);
			return vec_.at(index);
		}
		T operator[](size_t index) const
		{
			std::shared_lock lock(mutex_);
			return vec_[index];
		}
		bool empty() const
		{
			std::shared_lock lock(mutex_);
			return vec_.empty();
		}
		size_t size() const
		{
			std::shared_lock lock(mutex_);
			return vec_.size();
		}
		size_t max_size() const
		{
			std::shared_lock lock(mutex_);
			return vec_.max_size();
		}
		size_t capacity() const
		{
			std::shared_lock lock(mutex_);
			return vec_.capacity();
		}
		void reserve(size_t new_cap)
		{
			std::unique_lock lock(mutex_);
			vec_.reserve(new_cap);
		}
		void shrink_to_fit()
		{
			std::unique_lock lock(mutex_);
			vec_.shrink_to_fit();
		}

		void clear()
		{
			std::unique_lock lock(mutex_);
			vec_.clear();
		}
		void insert(size_t index, const T& value)
		{
			std::unique_lock lock(mutex_);
			vec_.insert(vec_.begin() + index, value);
		}
		void erase(size_t index)
		{
			std::unique_lock lock(mutex_);
			vec_.erase(vec_.begin() + index);
		}
		void push_back(const T& value)
		{
			std::unique_lock lock(mutex_);
			vec_.push_back(value);
		}
		void pop_back()
		{
			std::unique_lock lock(mutex_);
			vec_.pop_back();
		}
		void doing(size_t pos, doSingleFunc func)
		{
			std::unique_lock lock(mutex_);
			func(vec_, this->vec_.begin() + pos);
		}
		void doing(doContainerFunc func)
		{
			std::unique_lock lock(mutex_);
			func(vec_);
		}
		void doing(doLoopFunc func)
		{
			std::unique_lock lock(mutex_);
			for (auto it = vec_.begin(); it != vec_.end(); ++it)
			{
				func(vec_, it);
			}
		}

};

	/**
	* 仅可移动的线程安全的std::vector封装
	*/
	template <std::movable T, typename Alloc = std::allocator<T>>
	class VectorMove
	{
		using selfVec = std::vector<T, Alloc>;
		using it = std::vector<T, Alloc>::iterator;
		using doSingleFunc = std::function<void(it)>;
		using doContainerFunc = std::function<void(selfVec&)>;
		using doLoopFunc = std::function<void(selfVec&, it)>;
	private:
		mutable std::shared_mutex mutex_;
		selfVec vec_;
	public:
		VectorMove() = default;
		~VectorMove() = default;

		VectorMove(const VectorMove& ohter) = delete;
		VectorMove& operator=(const VectorMove& ohter) = delete;
		VectorMove(VectorMove&& other)
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			this->vec_ = std::move(other.vec_);
		}
		VectorMove& operator=(VectorMove&& other)
		{
			std::scoped_lock lock(mutex_, other.mutex_);
			this->vec_ = std::move(other.vec_);
			return *this;
		}

		selfVec take_all()
		{
			std::unique_lock lock(mutex_);
			selfVec result = std::move(vec_);
			vec_.clear();
			return result;
		}
		void move_all(selfVec&& vec)
		{
			std::unique_lock lock(mutex_);
			this->vec_ = std::move(vec);
		}
		T take(size_t index)
		{
			std::unique_lock lock(mutex_);
			auto tmp = std::move(vec_[index]);
			vec_.erase(vec_.begin() + index);
			return tmp;
		}

		bool empty() const
		{
			std::shared_lock lock(mutex_);
			return vec_.empty();
		}
		size_t size() const
		{
			std::shared_lock lock(mutex_);
			return vec_.size();
		}
		size_t max_size() const
		{
			std::shared_lock lock(mutex_);
			return vec_.max_size();
		}
		size_t capacity() const
		{
			std::shared_lock lock(mutex_);
			return vec_.capacity();
		}
		void reserve(size_t new_cap)
		{
			std::unique_lock lock(mutex_);
			vec_.reserve(new_cap);
		}
		void shrink_to_fit()
		{
			std::unique_lock lock(mutex_);
			vec_.shrink_to_fit();
		}

		void clear()
		{
			std::unique_lock lock(mutex_);
			vec_.clear();
		}
		void insert(size_t index, T&& value)
		{
			std::unique_lock lock(mutex_);
			vec_.insert(vec_.begin() + index, std::move(value));
		}
		void erase(size_t index)
		{
			std::unique_lock lock(mutex_);
			vec_.erase(vec_.begin() + index);
		}
		void push_back(T&& value)
		{
			std::unique_lock lock(mutex_);
			vec_.push_back(std::move(value));
		}
		void emplace_back(T&& value)
		{
			std::unique_lock lock(mutex_);
			vec_.emplace_back(std::move(value));
		}
		void push_back(const T& value) = delete;
		void emplace_back(const T& value) = delete;
		void pop_back()
		{
			std::unique_lock lock(mutex_);
			vec_.pop_back();
		}
		void doing(size_t pos, doSingleFunc func)
		{
			std::unique_lock lock(mutex_);
			func(this->vec_.begin() + pos);
		}
		void doing(doContainerFunc func)
		{
			std::unique_lock lock(mutex_);
			func(vec_);
		}
		void doing(doLoopFunc func)
		{
			std::unique_lock lock(mutex_);
			for (auto it = vec_.begin(); it != vec_.end(); ++it)
			{
				func(vec_, it);
			}
		}
	};
}