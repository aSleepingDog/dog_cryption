#include "crypto/hash/algorithm/SM3.h"

#define NSROOT dog_torch::crypto::hash::algorithm
#define DOG_DATA dog_torch::serialize::BinaryData

const NSROOT::Config NSROOT::SM3::CONFIG = Config("SM3", "32");

uint32_t NSROOT::SM3::CLMB(uint32_t i, uint64_t n)
{
	int temp = n % 32;
	return (i << temp) | i >> (32 - temp);
}
uint32_t NSROOT::SM3::SM3tick4B(dog_torch::serialize::BinaryData& data, uint64_t index)
{
	return (uint32_t)(data[4 * index] << 24) + (uint32_t)(data[4 * index + 1] << 16) + (uint32_t)(data[4 * index + 2] << 8) + (uint32_t)(data[4 * index + 3]);
}
uint32_t NSROOT::SM3::functionP1_SM3(dog_torch::serialize::BinaryData& data, uint64_t index)
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
uint32_t NSROOT::SM3::functionFF1_SM3(uint32_t a, uint32_t b, uint32_t c, int i)
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
uint32_t NSROOT::SM3::functionGG1_SM3(uint32_t a, uint32_t b, uint32_t c, int i)
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
void NSROOT::SM3::single_update(Data block, Data& value)
{
	if (block.size() != 64)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION("Error:block size is not 64 when SM3-256\n错误：在SM3-256时，数据分组block大小不为64"));
	}
	uint32_t tempN[8], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		uint32_t tempInt = 0;
		tempInt |= (uint32_t)value[i * 4] << 24;
		tempInt |= (uint32_t)value[i * 4 + 1] << 16;
		tempInt |= (uint32_t)value[i * 4 + 2] << 8;
		tempInt |= (uint32_t)value[i * 4 + 3];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	for (int i0 = 16; i0 < 68; i0++)
	{
		uint32_t W = functionP1_SM3(block, i0);
		for (int i1 = 0; i1 < 4; i1++)
		{
			block.push_back((uint8_t)(W << i1 * 8 >> 24));
		}
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		uint32_t W = SM3tick4B(block, i0) ^ SM3tick4B(block, i0 + 4);
		for (int i1 = 0; i1 < 4; i1++)
		{
			block.push_back((uint8_t)(W << i1 * 8 >> 24));
		}
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		uint32_t T = (i0 < 16) ? (0x79cc4519) : (0x7a879d8a);
		uint32_t SS1 = CLMB((CLMB(tempN[0], 12) + tempN[4] + CLMB(T, i0)), 7);
		uint32_t SS2 = SS1 ^ CLMB(tempN[0], 12);
		uint32_t TT1 = functionFF1_SM3(tempN[0], tempN[1], tempN[2], i0) + tempN[3] + SS2 + SM3tick4B(block, i0 + 68);
		uint32_t TT2 = functionGG1_SM3(tempN[4], tempN[5], tempN[6], i0) + tempN[7] + SS1 + SM3tick4B(block, i0);
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
			value[i * 4 + i0] = (uint8_t)((tempH[i] >> (24 - i0 * 8)) & 0xFF);
		}
	}
}
NSROOT::SM3::SM3(uint64_t effective) : Hash("SM3", effective)
{
	if (effective != 32)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION("Error:SM3 only support 32bits\n错误：SM3只支持32位"));
	}
	this->max_ = dog_torch::math::number::BIG_UINT64_MAX;
}
void NSROOT::SM3::init()
{
	this->is_padding_ = false;
}
DOG_DATA NSROOT::SM3::init_data() const
{
	return IV;
}
bool NSROOT::SM3::have_next_block(const BigInt& pos, const BigInt& total) const
{
	if (total > this->max_)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION("data size is too large"));
	}
	auto dur = (total - pos);
	return dur >= 64 ? true : !this->is_padding_;
}
DOG_DATA NSROOT::SM3::next_block(const Data& data, BigInt& pos, const BigInt& total)
{
	if (total > this->max_)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION("data size is too large"));
	}
	auto res = data.sub_by_len(pos.to_abs_uint64(), 64);
	pos += res.size();
	if (res.size() >= 64)
	{
		return res;
	}
	else
	{
		res.push_back(0x80);
		if (res.size() > (64 - 8))
		{
			while (res.size() < 64)
			{
				res.push_back(0x00);
			}
			return res;
		}
		else
		{
			while (res.size() < (64 - 8))
			{
				res.push_back(0x00);
			}
			Data num = (total * 8).to_byte_vector();
			this->is_padding_ = true;
			for (uint64_t i = 0; i < (8 - num.size()); i++)
			{
				res.push_back(0x00);
			}
			return res + num;
		}
	}
}
DOG_DATA NSROOT::SM3::next_block(std::istream& data, BigInt& pos, const BigInt& total)
{
	if (total > this->max_)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION("data size is too large"));
	}
	Data res(16);
	data.read((char*)res.data(), 16);
	for (uint64_t i = data.gcount(); i < 64; i++)
	{
		res.pop_back();
	}
	pos += data.gcount();
	if (res.size() >= 64)
	{
		return res;
	}
	else
	{
		res.push_back(0x80);
		if (res.size() > 56)
		{
			while (res.size() < 64)
			{
				res.push_back(0x00);
			}
			return res;
		}
		else
		{
			while (res.size() < 56)
			{
				res.push_back(0x00);
			}
			Data num = (total * 8).to_byte_vector();
			this->is_padding_ = true;
			return res + num;
		}
	}
}
NSROOT::update_func NSROOT::SM3::get_update() const
{
	return single_update;
}
NSROOT::trims_func NSROOT::SM3::get_trims() const
{
	return [](const Data& value) -> Data
		{
			return value;
		};
}
std::unique_ptr<NSROOT::Hash> NSROOT::SM3::clone() const
{
	return std::move(std::make_unique<SM3>(*this));
}
const DOG_DATA NSROOT::SM3::IV = "7380166F4914B2B9172442D7DA8A0600A96F30BC163138AAE38DEE4DB0FB0E4E";

#undef NSROOT
#undef DOG_DATA