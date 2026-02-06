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

	/**
	* 整数迭代器 用于解析特质的范围字符串
	*/
	class DOG_CRYPTION_API NumberIterator
	{
	private:
		uint64_t now_ = -1;
		uint64_t offset_ = 0;
		bool is_end_ = false;
		bool is_normal_;
		std::vector<uint64_t> list_;
	public:
		/**
		* 初始化迭代器
		* @param region_str 有效的范围字符串
		* @throw DOG_ERROR_INVALID_STR 范围字符串无效
		*/
		NumberIterator(std::string region_str);
		/**
		* 判断是否存在下一个数字
		* @result 是否存在下一个数字
		*/
		bool have_next();
		/**
		* 下一个数字
		*/
		uint64_t next();
	};

	/**
	* 判断范围字符串是否有效
	*/
	DOG_CRYPTION_API bool is_effective(std::string region_str);
	/**
	* 判断n是否落在范围字符串指定范围内
	*/
	DOG_CRYPTION_API bool is_fall(std::string region_str, uint64_t n);
	
	namespace array
	{
		/* XX,XX,XX|XX*/
		/**
		* 判断字符串是否满足XX,XX,XX|XX格式
		*/
		DOG_CRYPTION_API bool is_effective(std::string region_str);
		/**
		* 获得范围字符串的所有值
		*/
		DOG_CRYPTION_API std::vector<uint64_t> get_list(std::string region_str);
		/**
		* 判断n是否落在范围字符串指定范围内
		*/
		DOG_CRYPTION_API bool is_fall(std::string region_str, uint64_t n);
	}
	namespace gap
	{
		/*
		* [a,b]c -> a    ,a+c  ,a+2c , ...  ,b-2c ,b-1c ,b
		*/
		/**
		* 判断字符串是否满足[XX,XX]XX格式
		*/
		DOG_CRYPTION_API bool is_effective(std::string region_str);
		/**
		* 获得初始值 终值和步长
		*/
		DOG_CRYPTION_API std::array<uint64_t, 3> get_list(std::string region_str);
		/**
		* 判断n是否落在范围字符串指定范围内
		*/
		DOG_CRYPTION_API bool is_fall(std::string region_str, uint64_t n);
	}
}