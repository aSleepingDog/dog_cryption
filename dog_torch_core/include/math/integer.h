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

namespace dog_torch::math::integer
{
	using NumberException = dog_torch::utils::Exception;
	/**
	* 返回n的有效数位
	* e.g.
	*  0x0123 -> 2
	*  0x0024 -> 1
	*  0x0000 -> 1
	* @param n 无符号整数
	* @result 有效字节数
	*/
	DOG_CRYPTION_API uint8_t available_size(uint64_t n);
	/**
	* 返回n的有效数位
	* e.g.
	*  0x0123 -> 2
	*  0x0024 -> 1
	*  0x0000 -> 1
	* @param n 无符号整数
	* @result 有效字节数
	*/
	DOG_CRYPTION_API uint8_t available_size(uint32_t n);
	/**
	* 返回n的有效数位
	* e.g.
	*  0x0123 -> 2
	*  0x0024 -> 1
	*  0x0000 -> 1
	* @param n 无符号整数
	* @result 有效字节数
	*/
	DOG_CRYPTION_API uint8_t available_size(uint16_t n);

	/**
	* 返回n的第i位
	*  0x01 23 45 67 89 AB CD EF 取 7 位 -> 0x23
	*     8  7  6  5  4  3  2  1
	*/
	DOG_CRYPTION_API uint8_t pick_byte(uint64_t n, uint8_t i);
	/**
	* 返回n的第i位
	*  0x01 23 45 67 取 3 位 -> 0x23
	*     4  3  2  1
	*/
	DOG_CRYPTION_API uint8_t pick_byte(uint32_t n, uint8_t i);
	/**
	* 返回n的第i位
	*  0x01 23 取 1 位 -> 0x23
	*     2  1
	*/
	DOG_CRYPTION_API uint8_t pick_byte(uint16_t n, uint8_t i);

	/**
	* 循环移动
	*/
	DOG_CRYPTION_API uint64_t CRMB(uint64_t n, uint32_t i);
	/**
	* 循环移动
	*/
	DOG_CRYPTION_API uint32_t CRMB(uint32_t n, uint32_t i);
	/**
	* 循环移动
	*/
	DOG_CRYPTION_API uint16_t CRMB(uint16_t n, uint32_t i);
	/**
	* 循环移动
	*/
	DOG_CRYPTION_API uint8_t CRMB(uint8_t n, uint32_t i);
	/**
	* 循环移动
	*/
	DOG_CRYPTION_API uint64_t CLMB(uint64_t n, uint32_t i);
	/**
	* 循环移动
	*/
	DOG_CRYPTION_API uint32_t CLMB(uint32_t n, uint32_t i);
	/**
	* 循环移动
	*/
	DOG_CRYPTION_API uint16_t CLMB(uint16_t n, uint32_t i);
	/**
	* 循环移动
	*/
	DOG_CRYPTION_API uint8_t CLMB(uint8_t n, uint32_t i);

}
