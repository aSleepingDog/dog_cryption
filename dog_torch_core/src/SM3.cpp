#include "crypto/hash/SM3.h"
//SM3
const std::string dog_torch::crypto::hash::SM3::name = "SM3";
const std::string dog_torch::crypto::hash::SM3::effective_region = "32";
const dog_torch::crypto::hash::HashConfig dog_torch::crypto::hash::SM3::config = HashConfig(name, effective_region);

const dog_torch::serialize::Data dog_torch::crypto::hash::SM3::b256::IV = "7380166F4914B2B9172442D7DA8A0600A96F30BC163138AAE38DEE4DB0FB0E4E";
const dog_torch::math::number::BigInteger dog_torch::crypto::hash::SM3::b256::MAX = "18446744073709551615";
const uint64_t dog_torch::crypto::hash::SM3::b256::EFFECTIVE_SIZE = 32;
const uint64_t dog_torch::crypto::hash::SM3::b256::BLOCK_SIZE = 64;
const uint64_t dog_torch::crypto::hash::SM3::b256::NUMBER_SIZE = 8;

std::string dog_torch::crypto::hash::SM3::get_config(std::string name, uint64_t effective)
{
	return name + "-" + std::to_string(effective);
}
uint32_t dog_torch::crypto::hash::SM3::CLMB(uint32_t i, uint64_t n)
{
	int temp = n % 32;
	return (i << temp) | i >> (32 - temp);
}
uint32_t dog_torch::crypto::hash::SM3::SM3tick4B(dog_torch::serialize::Data& data, uint64_t index)
{
	return (uint32_t)(data[4 * index] << 24) + (uint32_t)(data[4 * index + 1] << 16) + (uint32_t)(data[4 * index + 2] << 8) + (uint32_t)(data[4 * index + 3]);
}
uint32_t dog_torch::crypto::hash::SM3::functionP1_SM3(dog_torch::serialize::Data& data, uint64_t index)
{
	uint32_t w1 = SM3tick4B(data, index - 16);
	uint32_t w2 = SM3tick4B(data, index - 9);
	uint32_t w3 = SM3tick4B(data, index - 3);
	uint32_t w4 = SM3tick4B(data, index - 13);
	uint32_t w5 = SM3tick4B(data, index - 6);
	uint32_t W0 = (w1 ^ w2 ^ (CLMB(w3, 15)));
	uint32_t _P = W0 ^ CLMB(W0, 15) ^ CLMB(W0, 23);
	return _P ^ CLMB(w4, 7) ^ w5;
}
uint32_t dog_torch::crypto::hash::SM3::functionFF1_SM3(uint32_t a, uint32_t b, uint32_t c, int i)
{
	if (i < 16)
	{
		return a ^ b ^ c;
	}
	else
	{
		return (a & b) | (a & c) | (b & c);
	}
}
uint32_t dog_torch::crypto::hash::SM3::functionGG1_SM3(uint32_t a, uint32_t b, uint32_t c, int i)
{
	if (i < 16)
	{
		return a ^ b ^ c;
	}
	else
	{
		return (a & b) | (~a & c);
	}
}

void dog_torch::crypto::hash::SM3::b256::single_update(dog_torch::serialize::Data plain, dog_torch::serialize::Data& change_value)
{
	if (plain.size() != 64)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION("Error:plain size is not 64 when SM3-256\n错误：在SM3-256时，数据分组plain大小不为64"));
	}
	dog_torch::serialize::Data tempBlock = std::move(plain);
	uint32_t tempN[8], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		uint32_t tempInt = 0;
		tempInt |= (uint32_t)change_value[i * 4] << 24;
		tempInt |= (uint32_t)change_value[i * 4 + 1] << 16;
		tempInt |= (uint32_t)change_value[i * 4 + 2] << 8;
		tempInt |= (uint32_t)change_value[i * 4 + 3];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	for (int i0 = 16; i0 < 68; i0++)
	{
		uint32_t W = functionP1_SM3(tempBlock, i0);
		for (int i1 = 0; i1 < 4; i1++)
		{
			tempBlock.push_back((uint8_t)(W << i1 * 8 >> 24));
		}
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		uint32_t W = SM3tick4B(tempBlock, i0) ^ SM3tick4B(tempBlock, i0 + 4);
		for (int i1 = 0; i1 < 4; i1++)
		{
			tempBlock.push_back((uint8_t)(W << i1 * 8 >> 24));
		}
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		uint32_t T = (i0 < 16) ? (0x79cc4519) : (0x7a879d8a);
		uint32_t SS1 = CLMB((CLMB(tempN[0], 12) + tempN[4] + CLMB(T, i0)), 7);
		uint32_t SS2 = SS1 ^ CLMB(tempN[0], 12);
		uint32_t TT1 = functionFF1_SM3(tempN[0], tempN[1], tempN[2], i0) + tempN[3] + SS2 + SM3tick4B(tempBlock, i0 + 68);
		uint32_t TT2 = functionGG1_SM3(tempN[4], tempN[5], tempN[6], i0) + tempN[7] + SS1 + SM3tick4B(tempBlock, i0);
		tempN[3] = tempN[2];
		tempN[2] = CLMB(tempN[1], 9);
		tempN[1] = tempN[0];
		tempN[0] = TT1;
		tempN[7] = tempN[6];
		tempN[6] = CLMB(tempN[5], 19);
		tempN[5] = tempN[4];
		tempN[4] = TT2 ^ CLMB(TT2, 9) ^ CLMB(TT2, 17);
	}
	for (int i0 = 0; i0 < 8; i0++)
	{
		tempH[i0] = tempH[i0] ^ tempN[i0];
		tempN[i0] = tempH[i0];
	}
	for (int i = 0; i < 8; i++)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			change_value[i * 4 + i0] = (uint8_t)((tempH[i] >> (24 - i0 * 8)) & 0xFF);
		}
	}
}
