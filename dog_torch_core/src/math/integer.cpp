#include "math/integer.h"

uint8_t dog_torch::math::integer::available_size(uint64_t n)
{
	if (n == 0) return 1;
	const int front_zero = std::countl_zero(n);
	return (63 - front_zero + 8) / 8;
}
uint8_t dog_torch::math::integer::available_size(uint32_t n)
{
	if (n == 0) return 1;
	const int front_zero = std::countl_zero(n);
	return (31 - front_zero + 8) / 8;
}
uint8_t dog_torch::math::integer::available_size(uint16_t n)
{
	if (n == 0) return 1;
	const int front_zero = std::countl_zero(n);
	return (15 - front_zero + 8) / 8;
}

uint8_t dog_torch::math::integer::pick_byte(uint64_t n, uint8_t i)
{
	if (i < 1 || i > 9)
	{
		throw NumberException(DOG_EXCEPTION_MSG_OPINION("Error:index out of range\n错误：索引超出范围"));
	}
	return (n >> ((i - 1) * 8)) & 0xff;
}
uint8_t dog_torch::math::integer::pick_byte(uint32_t n, uint8_t i)
{
	if (i < 1 || i > 5)
	{
		throw NumberException(DOG_EXCEPTION_MSG_OPINION("Error:index out of range\n错误：索引超出范围"));
	}
	return (n >> ((i - 1) * 8)) & 0xff;
}
uint8_t dog_torch::math::integer::pick_byte(uint16_t n, uint8_t i)
{
	if (i < 1 || i > 3)
	{
		throw NumberException(DOG_EXCEPTION_MSG_OPINION("Error:index out of range\n错误：索引超出范围"));
	}
	return (n >> ((i - 1) * 8)) & 0xff;
}

uint64_t dog_torch::math::integer::CRMB(uint64_t n, uint32_t i)
{
	i %= 64;
	return (n >> i) | (n << (64 - i));
}
uint32_t dog_torch::math::integer::CRMB(uint32_t n, uint32_t i)
{
	i %= 32;
	return (n >> i) | (n << (32 - i));
}
uint16_t dog_torch::math::integer::CRMB(uint16_t n, uint32_t i)
{
	i %= 16;
	return (n >> i) | (n << (16 - i));
}
uint8_t dog_torch::math::integer::CRMB(uint8_t n, uint32_t i)
{
	i %= 8;
	return (n >> i) | (n << (8 - i));
}
uint64_t dog_torch::math::integer::CLMB(uint64_t n, uint32_t i)
{
	i %= 64;
	return (n << i) | (n >> (64 - i));
}
uint32_t dog_torch::math::integer::CLMB(uint32_t n, uint32_t i)
{
	i %= 32;
	return (n << i) | (n >> (32 - i));
}
uint16_t dog_torch::math::integer::CLMB(uint16_t n, uint32_t i)
{
	i %= 16;
	return (n << i) | (n >> (16 - i));
}
uint8_t dog_torch::math::integer::CLMB(uint8_t n, uint32_t i)
{
	i %= 8;
	return (n >> i) | (n << (8 - i));
}