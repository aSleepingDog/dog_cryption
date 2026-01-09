#pragma once
#ifdef SHARED
	#include "export.h"
#else
	#define DOG_CRYPTION_API
#endif

#include <queue>
#include <array>
#include <regex>
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <utility>
#include <complex>
#include <iostream>
#include <algorithm>
#include <exception>
#include <functional>

#include "utils/Exception.h"
namespace dog_torch::math::region
{

	using NumberException = dog_torch::utils::Exception;

	class DOG_CRYPTION_API NumberIterator
	{
	private:
		uint64_t now_ = -1;
		uint64_t offset_ = 0;
		bool is_end_ = false;
		bool is_normal_;
		std::vector<uint64_t> list_;
	public:
		NumberIterator(std::string region_str);
		bool have_next();
		uint64_t next();
	};


	DOG_CRYPTION_API bool is_effective(std::string region_str);
	DOG_CRYPTION_API bool is_fall(std::string region_str, uint64_t n);
	
	namespace array
	{
		/* XX,XX,XX|XX*/
		DOG_CRYPTION_API bool is_effective(std::string region_str);
		DOG_CRYPTION_API std::vector<uint64_t> get_list(std::string region_str);
		DOG_CRYPTION_API bool is_fall(std::string region_str, uint64_t n);
	}
	namespace gap
	{
		/*
		* [a,b]c -> a    ,a+c  ,a+2c , ...  ,b-2c ,b-1c ,b
		*/
		DOG_CRYPTION_API bool is_effective(std::string region_str);
		DOG_CRYPTION_API std::array<uint64_t, 3> get_list(std::string region_str);
		DOG_CRYPTION_API bool is_fall(std::string region_str, uint64_t n);
	}
}