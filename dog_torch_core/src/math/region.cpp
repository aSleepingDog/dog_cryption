#include "math/region.h"

#define DOG_ERROR_INVALID_STR "Error:invalid region string"
#define DOG_ERROR_END_ITERATOR "Error:range iterator is end"

bool dog_torch::math::region::gap::is_effective(std::string region_str)
{
	//[XX,XX]XX ([]|)
	std::regex r("^\\[(0|[1-9][0-9]*),(\\$|((0|[1-9][0-9]*)))\\](0|[1-9][0-9]*)$");
	if (!std::regex_match(region_str, r))
	{
		return false;
	}
	std::array<uint64_t, 3> list;
	uint64_t i = 0;
	std::unique_ptr<uint64_t> n = nullptr;
	for (auto& c : region_str)
	{
		//if (c == ',' || c == ']' || c == ']')
		if (c == ',' || c == ']')
		{
			list[i] = *n;
			i++;
			n = nullptr;
		}
		else if (c == '[')
		{
			continue;
		}
		else if (c == '$')
		{
			list[i] = 0xffffffffffffffff;
			i++;
			n = nullptr;
		}
		else
		{
			if (n == nullptr)
			{
                n = std::make_unique<uint64_t>(0);
			}
			*n *= 10;
			*n += c - '0';
		}
	}
	if (n != nullptr)
	{
		list[2] = *n;
	}
	if (list[0] > list[1])
	{
		return false;
	}
	return true;
}
std::array<uint64_t, 3> dog_torch::math::region::gap::get_list(std::string region_str)
{
	if (!dog_torch::math::region::gap::is_effective(region_str))
	{
		throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_INVALID_STR));
	}
	std::array<uint64_t, 3> list = {0,0,0};
	uint64_t i = 0;
	std::unique_ptr<uint64_t> n = nullptr;
	for (auto& c : region_str)
	{
		//if (c == ',' || c == ']' || c == ']')
		if (c == ',' || c == ']')
		{
			list[i] = *n;
			i++;
			n = nullptr;
		}
		else if (c == '[')
		{
			continue;
		}
		else if (c == '$')
		{
			list[i] = 0xffffffffffffffff;
			i++;
			n = nullptr;
		}
		else
		{
			if (n == nullptr)
			{
				n = std::make_unique<uint64_t>(0);
			}
			*n *= 10;
			*n += c - '0';
		}
	}
	if (n != nullptr)
	{
		list[2] = *n;
	}
	return list;
}
bool dog_torch::math::region::gap::is_fall(std::string region_str, uint64_t n)
{
	std::array<uint64_t, 3> list = get_list(region_str);
	if (n < list[0] || n > list[1])
	{
		return false;
	}
	if (list[2] == 0)
	{
		return n == list[0];
	}
	if ((n - list[0]) % list[2] == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool dog_torch::math::region::array::is_effective(std::string region_str)
{
	// XX,XX
	std::regex r("^((0|[1-9][0-9]*))((,|\\|)(0|[1-9][0-9]*))*$");
	return std::regex_match(region_str, r);
}
std::vector<uint64_t> dog_torch::math::region::array::get_list(std::string region_str)
{
	if (!is_effective(region_str))
	{
		throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_INVALID_STR));
	}
	std::vector<uint64_t> list;
	std::unique_ptr<uint64_t> n = nullptr;
	for (auto& c : region_str)
	{
		if (c == ',' || c == '|')
		{
			list.push_back(*n);
			n = nullptr;
		}
		else
		{
			if (n == nullptr)
			{
				n = std::make_unique<uint64_t>(0);
			}
			*n *= 10;
			*n += c - '0';
		}
	}
	if (n != nullptr)
	{
		list.push_back(*n);
	}
	return list;
}
bool dog_torch::math::region::array::is_fall(std::string region_str, uint64_t n)
{
	std::vector<uint64_t> list = get_list(region_str);
	for (auto& i : list)
	{
		if (i == n)
		{
			return true;
		}
	}
	return false;
}

bool dog_torch::math::region::is_effective(std::string region_str)
{
	if (dog_torch::math::region::gap::is_effective(region_str))
	{
		return true;
	}
	else if (dog_torch::math::region::array::is_effective(region_str))
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool dog_torch::math::region::is_fall(std::string region_str, uint64_t n)
{
	if (dog_torch::math::region::gap::is_effective(region_str))
	{
		return dog_torch::math::region::gap::is_fall(region_str, n);
	}
	else if (dog_torch::math::region::array::is_effective(region_str))
	{
		return dog_torch::math::region::array::is_fall(region_str, n);
	}
	else
	{
		throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_INVALID_STR));
	}
}

dog_torch::math::region::NumberIterator::NumberIterator(std::string region_str)
{
	if (dog_torch::math::region::array::is_effective(region_str))
	{
		this->list_ = dog_torch::math::region::array::get_list(region_str);
		this->is_normal_ = true;
		if (this->list_.size() == 0)
		{
			this->is_end_ = true;
		}
		else
		{
			this->now_ = this->list_[0];
		}
	}
	else if (dog_torch::math::region::gap::is_effective(region_str))
	{
		auto list = dog_torch::math::region::gap::get_list(region_str);
		for (auto n : list)
		{
			this->list_.push_back(n);
		}
		this->is_normal_ = false;
		now_ = this->list_[0];
	}
	else
	{
		throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_INVALID_STR));
	}
}
bool dog_torch::math::region::NumberIterator::have_next()
{
	return !this->is_end_;
}
uint64_t dog_torch::math::region::NumberIterator::next()
{
	if (!have_next())
	{
		throw NumberException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_END_ITERATOR));
	}
	uint64_t result = 0;
	if (this->is_normal_)
	{
		result = this->now_;
		this->offset_++;
		if (this->offset_ == this->list_.size())
		{
			this->is_end_ = true;
		}
		else
		{
			this->now_ = this->list_[this->offset_];
		}

	}
	else
	{
		result = this->now_;
		this->offset_++;
		this->now_ += this->list_[2];
		if ((this->list_[2] == 0 && this->now_ >= this->list_[1]) || this->now_ > this->list_[1])
		{
			this->is_end_ = true;
		}
	}
	return result;
}


#undef DOG_ERROR_INVALID_STR
#undef DOG_ERROR_END_ITERATOR